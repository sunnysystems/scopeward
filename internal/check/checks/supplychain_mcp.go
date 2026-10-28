package checks

import (
	"context"
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(mcpServerUnpinned{}) }

// mcpServerUnpinned flags MCP servers a committed config launches from code that
// can change without a commit to the repository: a package with no exact
// version, an image by tag. Every developer whose agent loads the config runs
// that code on their own machine, with their credentials and the agent's
// tools — a dependency that bypasses the lockfile, Dependabot and review.
// The org's own packages and images are first-party, as same-org actions are.
type mcpServerUnpinned struct{}

func (mcpServerUnpinned) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "supplychain.mcp-server-unpinned",
		Title:           "MCP servers launched from unpinned code",
		Axis:            model.AxisSupplyChain,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataAgentFiles},
		Description:     "Committed MCP configs that launch servers through npx, uvx or docker without an exact version or digest.",
	}
}

func (c mcpServerUnpinned) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		var servers []map[string]any
		for _, srv := range r.MCPServers {
			if srv.Unpinned == "" || srv.FirstParty {
				continue
			}
			servers = append(servers, map[string]any{
				"file": srv.File, "name": srv.Name, "launch": srv.Launch, "why": srv.Unpinned,
			})
		}
		if len(servers) == 0 {
			continue
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    fmt.Sprintf("%s/%s makes every developer's agent launch %s from unpinned code", s.Org.Login, r.Name, plural(len(servers), "MCP server")),
			Severity: model.SevMedium,
			Axis:     model.AxisSupplyChain,
			Resource: repoRef(s.Org.Login, r),
			Evidence: map[string]any{"repo": r.Name, "servers": servers},
			Description: "A committed MCP config makes every developer's agent run these servers on their own machine, with their credentials and the agent's tools. " +
				"Without an exact version or digest, whoever publishes the next release of the package, or pushes the tag, decides what runs, outside the lockfile, Dependabot and code review.",
			Remediation: "Pin each server to what was reviewed: an exact version (npx -y pkg@1.2.3, uvx pkg==1.2.3) or an image digest (image@sha256:…), and update it deliberately.",
			DocsURL:     "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices",
			Volume:      len(servers),
		})
	}
	return out
}
