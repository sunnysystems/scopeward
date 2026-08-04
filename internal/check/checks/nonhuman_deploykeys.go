package checks

import (
	"context"
	"strconv"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(writableDeployKey{}) }

// writableDeployKey flags deploy keys with write access. A deploy key is a
// non-human credential that often outlives the person who created it and is
// rarely rotated; a writable one is effectively an unattributed push credential.
type writableDeployKey struct{}

func (writableDeployKey) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.deploy-key-write",
		Title:           "Writable deploy keys",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevHigh,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataDeployKeys},
		Description:     "Deploy keys that grant write (push) access to a repository.",
	}
}

func (c writableDeployKey) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	gitlab := s.Provider == model.ProviderGitLab
	docs := "https://docs.github.com/authentication/connecting-to-github-with-ssh/managing-deploy-keys"
	if gitlab {
		docs = "https://docs.gitlab.com/ee/user/project/deploy_keys/"
	}

	var out []model.Finding
	for _, r := range activeRepos(s) {
		for _, k := range r.DeployKeys {
			if k.ReadOnly {
				continue
			}
			ev := map[string]any{"repo": r.Name, "key_id": strconv.FormatInt(k.ID, 10), "title": k.Title}
			if k.ExpiresAt != nil {
				ev["expires_at"] = k.ExpiresAt.Format("2006-01-02")
			}
			f := model.Finding{
				CheckID:     c.Meta().ID,
				Title:       "Writable deploy key \"" + k.Title + "\" on " + repoDisplay(s, r),
				Severity:    model.SevHigh,
				Axis:        model.AxisNonHuman,
				Resource:    repoResource(s, r),
				Evidence:    ev,
				Description: "This SSH deploy key can push to the repository. Deploy keys are machine credentials with no owner, no 2FA, and usually no rotation, so a leaked key is durable write access that is hard to attribute.",
				Remediation: "Confirm the key is still needed; prefer a read-only key or a short-lived token. Remove unknown or stale keys and rotate on schedule.",
				DocsURL:     docs,
			}
			// The gh fixer only applies to GitHub; the glab/API equivalent lands
			// with the fixer abstraction (#10). On GitLab the finding carries the
			// key id so a fixer can build the revoke later.
			if !gitlab {
				f = withFix(f, ghDeleteDeployKey(s.Org.Login, r.Name, strconv.FormatInt(k.ID, 10)))
			}
			out = append(out, f)
		}
	}
	return out
}
