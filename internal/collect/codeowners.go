package collect

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// codeownersLocations are the paths GitHub recognizes for a CODEOWNERS file, in
// the order it resolves them.
var codeownersLocations = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

// teamMentionRe matches a team code-owner reference: @org/team (a slash
// distinguishes it from an @individual or a bare email owner).
var teamMentionRe = regexp.MustCompile(`@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9._-]+`)

// fetchCodeowners looks for a CODEOWNERS file in the recognized locations and,
// if found, returns the distinct team references (@org/team) it assigns. The
// bool is false when no file exists in any location. It stops at the first
// location that resolves.
func fetchCodeowners(ctx context.Context, client *ghclient.Client, org, repo string) (present bool, teams []string, err error) {
	for _, path := range codeownersLocations {
		content, found, ferr := fetchFileContent(ctx, client, org, repo, path)
		if ferr != nil {
			return false, nil, ferr
		}
		if found {
			return true, parseCodeownersTeams(content), nil
		}
	}
	return false, nil, nil
}

// fetchFileContent gets a single file's decoded text. found is false on 404.
func fetchFileContent(ctx context.Context, client *ghclient.Client, org, repo, path string) (string, bool, error) {
	var file struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		Type     string `json:"type"`
	}
	if _, err := client.Get(ctx, "/repos/"+org+"/"+repo+"/contents/"+path, nil, &file); err != nil {
		if ghclient.StatusCode(err) == 404 {
			return "", false, nil
		}
		return "", false, err
	}
	if file.Type != "file" {
		return "", false, nil
	}
	if file.Encoding == "base64" {
		if decoded, derr := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", "")); derr == nil {
			return string(decoded), true, nil
		}
	}
	return file.Content, true, nil
}

// parseCodeownersTeams extracts the distinct @org/team references from a
// CODEOWNERS file, skipping comments.
func parseCodeownersTeams(content string) []string {
	seen := map[string]bool{}
	var teams []string
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, m := range teamMentionRe.FindAllString(line, -1) {
			if !seen[m] {
				seen[m] = true
				teams = append(teams, m)
			}
		}
	}
	return teams
}

// applyCodeowners records the outcome of a CODEOWNERS lookup onto a repo.
func applyCodeowners(r *model.Repo, present bool, teams []string) {
	p := present
	r.CodeownersPresent = &p
	r.CodeownersTeams = teams
}
