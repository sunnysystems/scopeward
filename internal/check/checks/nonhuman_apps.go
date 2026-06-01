package checks

import (
	"context"
	"sort"
	"strconv"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(appBroadPermissions{}) }

// appBroadPermissions flags installed GitHub Apps that hold write or admin
// permissions — non-human identities that can change code or settings. An app
// with admin, or with write across all repositories, is the highest concern.
type appBroadPermissions struct{}

func (appBroadPermissions) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.app-broad-permissions",
		Title:           "GitHub Apps with write/admin",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataAppInstallations},
		Description:     "Installed GitHub Apps holding write or admin permissions on org resources.",
	}
}

func (c appBroadPermissions) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, app := range s.AppInstallations {
		elevated, hasAdmin, hasWrite := elevatedPermissions(app.Permissions)
		if !hasAdmin && !hasWrite {
			continue // read-only apps are not flagged
		}

		sev := model.SevMedium
		if hasAdmin || (hasWrite && app.RepositorySelection == "all") {
			sev = model.SevHigh
		}

		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "GitHub App \"" + app.AppSlug + "\" has elevated permissions",
			Severity: sev,
			Axis:     model.AxisNonHuman,
			Resource: model.ResourceRef{
				Type: "app",
				ID:   strconv.FormatInt(app.AppID, 10),
				Name: app.AppSlug,
				URL:  "https://github.com/apps/" + app.AppSlug,
			},
			Evidence: map[string]any{
				"app_slug":             app.AppSlug,
				"repository_selection": app.RepositorySelection,
				"elevated_permissions": elevated,
			},
			Description: "This app is a machine identity that can act on your repositories. Write or admin permissions mean a compromise of the app (or its publisher) translates directly into write access to your code or settings.",
			Remediation: "Confirm the app is still in use and trusted; reduce its permissions to read where possible and limit it to selected repositories rather than all.",
			DocsURL:     "https://docs.github.com/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
		})
	}
	return out
}

// elevatedPermissions returns the sorted "perm:level" pairs that are write/admin,
// plus whether any admin or any write level is present.
func elevatedPermissions(perms map[string]string) (elevated []string, hasAdmin, hasWrite bool) {
	for name, level := range perms {
		switch level {
		case "admin":
			hasAdmin = true
			elevated = append(elevated, name+":admin")
		case "write":
			hasWrite = true
			elevated = append(elevated, name+":write")
		}
	}
	sort.Strings(elevated)
	return elevated, hasAdmin, hasWrite
}
