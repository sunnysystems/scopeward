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
		RequiresData:    []model.DataKind{model.DataDeployKeys},
		Description:     "Deploy keys that grant write (push) access to a repository.",
	}
}

func (c writableDeployKey) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.Repos {
		for _, k := range r.DeployKeys {
			if k.ReadOnly {
				continue
			}
			out = append(out, withFix(model.Finding{
				CheckID:     c.Meta().ID,
				Title:       "Writable deploy key \"" + k.Title + "\" on " + s.Org.Login + "/" + r.Name,
				Severity:    model.SevHigh,
				Axis:        model.AxisNonHuman,
				Resource:    repoRef(s.Org.Login, r),
				Evidence:    map[string]any{"repo": r.Name, "key_id": strconv.FormatInt(k.ID, 10), "title": k.Title},
				Description: "This SSH deploy key can push to the repository. Deploy keys are machine credentials with no owner, no 2FA, and usually no rotation, so a leaked key is durable write access that is hard to attribute.",
				Remediation: "Confirm the key is still needed; prefer a read-only key or a short-lived token. Remove unknown or stale keys and rotate on schedule.",
				DocsURL:     "https://docs.github.com/authentication/connecting-to-github-with-ssh/managing-deploy-keys",
			}, ghDeleteDeployKey(s.Org.Login, r.Name, strconv.FormatInt(k.ID, 10))))
		}
	}
	return out
}
