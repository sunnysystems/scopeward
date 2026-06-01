package collect

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// officialActionOwners are GitHub-maintained action namespaces commonly pinned
// by tag; we don't flag these as unpinned to keep the signal focused on
// third-party actions, which are the real supply-chain risk.
var officialActionOwners = map[string]bool{"actions": true, "github": true}

var (
	usesRe = regexp.MustCompile(`(?m)uses:\s*["']?([^"'\s#]+)`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// fetchWorkflowIssues reads a repo's Actions workflow files and returns
// supply-chain concerns. A repo with no workflows (404 on the dir) yields no
// issues and no error.
func fetchWorkflowIssues(ctx context.Context, client *ghclient.Client, org, repo string) ([]model.WorkflowIssue, error) {
	type contentItem struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		Type     string `json:"type"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}

	var dir []contentItem
	if _, err := client.Get(ctx, "/repos/"+org+"/"+repo+"/contents/.github/workflows", nil, &dir); err != nil {
		if ghclient.StatusCode(err) == 404 {
			return nil, nil // no workflows
		}
		return nil, err
	}

	var issues []model.WorkflowIssue
	for _, item := range dir {
		if item.Type != "file" || !isWorkflowFile(item.Name) {
			continue
		}
		var file contentItem
		if _, err := client.Get(ctx, "/repos/"+org+"/"+repo+"/contents/"+item.Path, nil, &file); err != nil {
			return issues, err
		}
		content := file.Content
		if file.Encoding == "base64" {
			decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
			if err == nil {
				content = string(decoded)
			}
		}
		issues = append(issues, scanWorkflow(item.Name, content)...)
	}
	return issues, nil
}

func isWorkflowFile(name string) bool {
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

// scanWorkflow inspects one workflow's text for supply-chain issues. It is pure
// (no I/O) so it can be unit-tested directly.
func scanWorkflow(file, content string) []model.WorkflowIssue {
	var issues []model.WorkflowIssue

	for _, m := range usesRe.FindAllStringSubmatch(content, -1) {
		ref := m[1]
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue // local or docker action
		}
		at := strings.LastIndex(ref, "@")
		if at < 0 {
			continue // no version specified (uncommon)
		}
		action, version := ref[:at], ref[at+1:]
		owner, _, _ := strings.Cut(action, "/")
		if officialActionOwners[owner] {
			continue
		}
		if !shaRe.MatchString(version) {
			issues = append(issues, model.WorkflowIssue{File: file, Kind: "unpinned-action", Detail: ref})
		}
	}

	if hasUnsafeTrigger(content) {
		issues = append(issues, model.WorkflowIssue{File: file, Kind: "pull-request-target", Detail: "pull_request_target"})
	}
	return issues
}

// hasUnsafeTrigger reports whether the workflow uses the pull_request_target
// trigger, which runs with repo secrets in the context of fork PRs.
func hasUnsafeTrigger(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // comment
		}
		if strings.Contains(trimmed, "pull_request_target") {
			return true
		}
	}
	return false
}
