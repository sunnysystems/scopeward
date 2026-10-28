package collect

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// agentPath is a file convention an AI agent reads from a repository. match is
// an exact path, or a directory ending in "/" for every file under it (only
// those ending in suffix, when set). Every entry cites where the convention is
// documented: file names move fast, and the source is what keeps the table
// reviewable.
type agentPath struct {
	kind, match, suffix, source string
}

var agentPaths = []agentPath{
	{kind: "instructions", match: "AGENTS.md", source: "https://agents.md"},
	{kind: "instructions", match: "CLAUDE.md", source: "https://code.claude.com/docs/en/memory"},
	{kind: "instructions", match: "CLAUDE.local.md", source: "https://code.claude.com/docs/en/memory"},
	{kind: "instructions", match: ".claude/CLAUDE.md", source: "https://code.claude.com/docs/en/memory"},
	{kind: "instructions", match: ".claude/agents/", suffix: ".md", source: "https://code.claude.com/docs/en/sub-agents"},
	{kind: "instructions", match: ".claude/commands/", suffix: ".md", source: "https://code.claude.com/docs/en/slash-commands"},
	{kind: "instructions", match: "GEMINI.md", source: "https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/gemini-md.md"},
	{kind: "instructions", match: ".github/copilot-instructions.md", source: "https://docs.github.com/copilot/how-tos/configure-custom-instructions/add-repository-instructions"},
	{kind: "instructions", match: ".github/instructions/", suffix: ".instructions.md", source: "https://docs.github.com/copilot/how-tos/configure-custom-instructions/add-repository-instructions"},
	{kind: "instructions", match: ".cursorrules", source: "https://cursor.com/docs/context/rules"},
	{kind: "instructions", match: ".cursor/rules/", source: "https://cursor.com/docs/context/rules"},
	{kind: "settings", match: ".claude/settings.json", source: "https://code.claude.com/docs/en/settings"},
	{kind: "settings", match: ".claude/settings.local.json", source: "https://code.claude.com/docs/en/settings"},
	// Gemini's project settings also declare MCP servers (mcpServers).
	{kind: "settings", match: ".gemini/settings.json", source: "https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md"},
	{kind: "mcp", match: ".mcp.json", source: "https://code.claude.com/docs/en/mcp"},
	{kind: "mcp", match: ".cursor/mcp.json", source: "https://cursor.com/docs/context/mcp"},
	{kind: "mcp", match: ".vscode/mcp.json", source: "https://code.visualstudio.com/docs/copilot/customization/mcp-servers"},
}

// agentConfigDirs are the root directories the table reaches into. Only these
// are listed in full; the rest of the tree is never walked, which keeps the
// cost at one request per repository plus one per directory present, however
// large the repository. Instruction files nested deeper (a subproject's own
// AGENTS.md) are not read.
var agentConfigDirs = map[string]bool{".github": true, ".claude": true, ".cursor": true, ".vscode": true, ".gemini": true}

// classifyAgentPath names the kind of agent-control file a repository path is,
// or "" when it is none.
func classifyAgentPath(p string) string {
	for _, a := range agentPaths {
		if strings.HasSuffix(a.match, "/") {
			if strings.HasPrefix(p, a.match) && strings.HasSuffix(p, a.suffix) {
				return a.kind
			}
		} else if p == a.match {
			return a.kind
		}
	}
	return ""
}

// agentFiles is what a repository's agent-control files say.
type agentFiles struct {
	files    []model.AgentControlFile
	servers  []model.MCPServer
	settings []model.AgentSettings
}

type treeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"` // "blob" | "tree"
	SHA  string `json:"sha"`
}

type treeDTO struct {
	Tree      []treeEntry `json:"tree"`
	Truncated bool        `json:"truncated"`
}

// errTreeTruncated reports a directory listing GitHub cut short: what is
// missing from it was not seen, so the repository is not assessed.
var errTreeTruncated = errors.New("directory listing truncated")

// fetchAgentFiles lists the root of the default branch and the agents' config
// directories in it, then reads the MCP configs and agent settings found. An
// empty repository yields nothing and no error.
func fetchAgentFiles(ctx context.Context, client *ghclient.Client, org, repo, branch, owner string) (agentFiles, error) {
	var out agentFiles
	if branch == "" {
		return out, nil
	}
	base := "/repos/" + org + "/" + repo + "/git/trees/"
	var root treeDTO
	if _, err := client.Get(ctx, base+branch, nil, &root); err != nil {
		if code := ghclient.StatusCode(err); code == 404 || code == 409 {
			return out, nil // empty repository
		}
		return out, err
	}
	if root.Truncated {
		return out, errTreeTruncated
	}

	var paths []string
	for _, e := range root.Tree {
		switch {
		case e.Type == "blob":
			paths = append(paths, e.Path)
		case e.Type == "tree" && agentConfigDirs[e.Path]:
			var sub treeDTO
			if _, err := client.Get(ctx, base+e.SHA, url.Values{"recursive": {"1"}}, &sub); err != nil {
				return out, err
			}
			if sub.Truncated {
				return out, errTreeTruncated
			}
			for _, se := range sub.Tree {
				if se.Type == "blob" {
					paths = append(paths, e.Path+"/"+se.Path)
				}
			}
		}
	}
	sort.Strings(paths)

	for _, p := range paths {
		kind := classifyAgentPath(p)
		if kind == "" {
			continue
		}
		out.files = append(out.files, model.AgentControlFile{Path: p, Kind: kind})
		if kind == "instructions" {
			continue
		}
		content, found, err := fetchFileContent(ctx, client, org, repo, p)
		if err != nil {
			return out, err
		}
		if !found {
			continue
		}
		out.servers = append(out.servers, parseMCPConfig(p, content, owner)...)
		if strings.HasPrefix(p, ".claude/") {
			if st, ok := parseClaudeSettings(p, content); ok {
				out.settings = append(out.settings, st)
			}
		}
	}
	return out, nil
}

// mcpConfig covers both shapes in use: "mcpServers" (Claude Code, Cursor,
// Gemini) and "servers" (VS Code).
type mcpConfig struct {
	MCPServers map[string]mcpServerDTO `json:"mcpServers"`
	Servers    map[string]mcpServerDTO `json:"servers"`
}

type mcpServerDTO struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
	HTTPURL string   `json:"httpUrl"`
}

// parseMCPConfig reads the servers an MCP config declares. A file that does
// not parse yields none. owner is the org, whose own packages are first-party.
func parseMCPConfig(file, content, owner string) []model.MCPServer {
	var cfg mcpConfig
	if err := json.Unmarshal(stripJSONC(content), &cfg); err != nil {
		return nil
	}
	all := map[string]mcpServerDTO{}
	for name, s := range cfg.Servers {
		all[name] = s
	}
	for name, s := range cfg.MCPServers {
		all[name] = s
	}
	out := make([]model.MCPServer, 0, len(all))
	for _, name := range sortedKeys(all) {
		s := all[name]
		srv := model.MCPServer{File: file, Name: name}
		if url := firstNonEmpty(s.URL, s.HTTPURL); url != "" || s.Type == "http" || s.Type == "sse" {
			srv.Remote, srv.Launch = true, url
		} else {
			srv.Launch = strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
			srv.Package, srv.Unpinned = launchPinning(s.Command, s.Args)
			srv.FirstParty = srv.Package != "" && isFirstPartyPackage(srv.Package, owner)
		}
		out = append(out, srv)
	}
	return out
}

var (
	exactNPMVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)
	exactPyVersionRe  = regexp.MustCompile(`==\s*[0-9][0-9A-Za-z.+!-]*$`)
)

// launchPinning names the package or image an MCP server is launched from and,
// when the code behind it can change without a commit to this repository, why.
// A command that is not a package runner (node on a file in the repo, an
// installed binary) launches nothing from a registry and is not judged here.
func launchPinning(command string, args []string) (pkg, unpinned string) {
	cmd := strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(command, `\`, "/"))), ".cmd")
	switch cmd {
	case "npx", "pnpx", "bunx":
		return npmPinning(packageArg(args, "-p", "--package"))
	case "pnpm", "yarn", "bun":
		if len(args) > 0 && (args[0] == "dlx" || args[0] == "x") {
			return npmPinning(packageArg(args[1:], "-p", "--package"))
		}
	case "npm":
		if len(args) > 0 && (args[0] == "exec" || args[0] == "x") {
			for _, a := range args[1:] {
				if a == "--" {
					break
				}
				if a == "--no" || a == "--no-install" || a == "--yes=false" {
					return "", "" // refuses to install: runs what the lockfile put there
				}
			}
			return npmPinning(packageArg(args[1:], "-p", "--package"))
		}
	case "uvx", "pipx":
		rest := args
		if cmd == "pipx" {
			if len(rest) == 0 || rest[0] != "run" {
				return "", ""
			}
			rest = rest[1:]
		}
		spec := packageArg(rest, "--from", "--spec")
		switch {
		case spec == "":
			return "", ""
		case exactPyVersionRe.MatchString(spec):
			return spec, ""
		case strings.Contains(spec, "@") && !strings.HasSuffix(spec, "@latest"):
			return spec, ""
		default:
			return spec, "no exact version: the next release of " + spec + " runs on the next launch"
		}
	case "docker", "podman":
		if img := dockerImage(args); img != "" {
			if strings.Contains(img, "@sha256:") {
				return img, ""
			}
			return img, "image by tag, not digest: whoever can push " + img + " decides what runs"
		}
	}
	return "", ""
}

// packageArg is the package a runner launches: the value of a package flag when
// one is given, else the first argument that is not a flag.
func packageArg(args []string, flags ...string) string {
	for i, a := range args {
		for _, f := range flags {
			if a == f && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(a, f+"=") {
				return strings.TrimPrefix(a, f+"=")
			}
		}
	}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func npmPinning(spec string) (string, string) {
	if spec == "" {
		return "", ""
	}
	// The version follows the last "@" that is not a scope's leading one.
	name, version := spec, ""
	if i := strings.LastIndex(spec, "@"); i > 0 {
		name, version = spec[:i], spec[i+1:]
	}
	if exactNPMVersionRe.MatchString(version) {
		return spec, ""
	}
	if version == "" {
		return spec, "no version: unless the lockfile installs " + name + ", npm fetches whatever is latest on each launch"
	}
	return spec, "version \"" + version + "\" is a range or tag: npm resolves " + name + " to whatever matches on each launch"
}

// dockerValueFlags take a value as the next argument, which is not the image.
var dockerValueFlags = map[string]bool{
	"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true,
	"--mount": true, "--name": true, "-p": true, "--publish": true, "--network": true,
	"-w": true, "--workdir": true, "-u": true, "--user": true, "--entrypoint": true,
	"--platform": true, "-l": true, "--label": true, "--add-host": true,
}

func dockerImage(args []string) string {
	if len(args) == 0 || args[0] != "run" {
		return ""
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case dockerValueFlags[a]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return a
		}
	}
	return ""
}

// isFirstPartyPackage reports whether a package or image belongs to the org: an
// npm scope or a ghcr.io namespace named after it. Same reasoning as same-org
// actions (#38): it sits behind the org's own review.
func isFirstPartyPackage(pkg, owner string) bool {
	if owner == "" {
		return false
	}
	p := strings.ToLower(pkg)
	o := strings.ToLower(owner)
	return strings.HasPrefix(p, "@"+o+"/") || strings.HasPrefix(p, "ghcr.io/"+o+"/")
}

// claudeSettingsDTO is the slice of Claude Code settings this check reads.
type claudeSettingsDTO struct {
	Permissions struct {
		Allow       []string `json:"allow"`
		DefaultMode string   `json:"defaultMode"`
	} `json:"permissions"`
}

// broadShellRuleRe matches allow rules that approve every shell command: the
// bare tool name, or a wildcard specifier.
var broadShellRuleRe = regexp.MustCompile(`^Bash(\(\s*\*?\s*(:\s*\*)?\s*\))?$`)

func parseClaudeSettings(file, content string) (model.AgentSettings, bool) {
	var dto claudeSettingsDTO
	if err := json.Unmarshal(stripJSONC(content), &dto); err != nil {
		return model.AgentSettings{}, false
	}
	st := model.AgentSettings{File: file, DefaultMode: dto.Permissions.DefaultMode}
	for _, rule := range dto.Permissions.Allow {
		if broadShellRuleRe.MatchString(strings.TrimSpace(rule)) {
			st.BroadAllow = append(st.BroadAllow, rule)
		}
	}
	return st, true
}

// stripJSONC turns JSON with comments and trailing commas — which VS Code and
// Cursor accept in their config files — into JSON, leaving string contents
// untouched: comments go in one pass, then commas left before a closing
// bracket in a second, both skipping over strings.
func stripJSONC(s string) []byte {
	return dropTrailingCommas(dropComments(s))
}

func dropComments(s string) string {
	var b strings.Builder
	inStr, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			b.WriteByte(c)
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
			b.WriteByte(c)
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			i += 2
			for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
				i++
			}
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func dropTrailingCommas(s string) []byte {
	var b strings.Builder
	inStr, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == ',':
			j := i + 1
			for j < len(s) && strings.IndexByte(" \t\r\n", s[j]) >= 0 {
				j++
			}
			if j < len(s) && (s[j] == '}' || s[j] == ']') {
				continue
			}
		}
		b.WriteByte(c)
	}
	return []byte(b.String())
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
