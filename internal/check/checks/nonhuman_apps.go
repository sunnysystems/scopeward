package checks

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(appInventory{})
	check.Register(appDangerousPermissions{})
}

// dangerousAppPermissions are the GitHub App permissions where a compromise
// escalates beyond the code the app was installed to work on: it reaches the
// organization's configuration, its membership, its secrets, or its CI.
//
// The list is deliberately narrow. Write on contents, checks, statuses, pull
// requests, issues or deployments is precisely what a CI, deploy or IaC
// integration is installed to do — flagging those produced a permanent finding
// on every organization that automates anything, clearable only by uninstalling
// a working integration. These are different in kind: they let an app grant
// itself more, or take over what runs.
//
// The value is why it matters, used verbatim in the finding so the report says
// what the permission enables rather than only naming it.
var dangerousAppPermissions = map[string]string{
	"administration":                   "change repository settings, including removing branch protection",
	"organization_administration":      "change organization-wide settings",
	"members":                          "add and remove organization members and change team membership",
	"organization_custom_roles":        "redefine what a role is allowed to do",
	"organization_hooks":               "add a webhook that receives every organization event",
	"organization_self_hosted_runners": "register a runner that executes workflow code",
	"organization_secrets":             "overwrite the secrets every workflow runs with",
	"secrets":                          "overwrite the secrets a repository's workflows run with",
	"workflows":                        "modify workflow files, which is arbitrary code execution in CI",
}

func appRef(app model.AppInstallation) model.ResourceRef {
	return model.ResourceRef{
		Type: "app",
		ID:   strconv.FormatInt(app.AppID, 10),
		Name: app.AppSlug,
		URL:  "https://github.com/apps/" + app.AppSlug,
	}
}

// appInventory lists every installed GitHub App with the elevated permissions it
// holds. Apps are accepted, not eliminated: an org that runs CI, deploys, or an
// IaC integration necessarily has machine identities with write, and an app's
// permission set is declared by its author — an installing org cannot narrow it.
// So this is an inventory line reported at info, and what it asks for is review
// rather than removal.
type appInventory struct{}

func (appInventory) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.app-inventory",
		Title:           "Installed GitHub Apps",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevInfo,
		RequiresData:    []model.DataKind{model.DataAppInstallations},
		Description:     "Inventory of installed GitHub Apps and the elevated permissions each holds.",
	}
}

func (c appInventory) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if len(s.AppInstallations) == 0 {
		return nil
	}
	summary := make([]map[string]any, 0, len(s.AppInstallations))
	var withWrite, allRepos int
	for _, app := range s.AppInstallations {
		elevated, hasAdmin, hasWrite := elevatedPermissions(app.Permissions)
		if hasAdmin || hasWrite {
			withWrite++
		}
		if app.RepositorySelection == "all" {
			allRepos++
		}
		summary = append(summary, map[string]any{
			"app_slug":             app.AppSlug,
			"repository_selection": app.RepositorySelection,
			"elevated_permissions": elevated,
		})
	}
	sort.Slice(summary, func(i, j int) bool {
		return summary[i]["app_slug"].(string) < summary[j]["app_slug"].(string)
	})

	return []model.Finding{{
		CheckID: c.Meta().ID,
		Title: fmt.Sprintf("%d GitHub App(s) installed — %d with write or admin, %d scoped to all repositories",
			len(s.AppInstallations), withWrite, allRepos),
		Severity: model.SevInfo,
		Axis:     model.AxisNonHuman,
		Resource: orgRef(s.Org),
		Evidence: map[string]any{"apps": summary},
		Description: "Each installed app is a machine identity that acts on your repositories with a credential nobody rotates by hand. " +
			"Write permissions are listed rather than flagged: an app's permission set is chosen by its author, so an installing organization cannot narrow it — the levers are uninstalling, or limiting the app to selected repositories.",
		Remediation: "Review the list: confirm each app is still in use and still trusted, tie it to an owner, and narrow repository_selection from all to selected wherever the app does not need every repository.",
		DocsURL:     "https://docs.github.com/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
	}}
}

// appDangerousPermissions flags installed apps holding a permission from the
// narrow set that escalates past the app's own job — org settings, membership,
// secrets, runners, or workflow files.
//
// It replaces a check that flagged any write at all. That one could not reach
// zero for any organization with automation, which put an unreachable floor
// under the score, trained users to ignore the non-human axis (the product's
// differentiator), and pushed people toward suppressing something the tool
// should model natively. This one is clearable, because the apps it names really
// are ones to question.
type appDangerousPermissions struct{}

func (appDangerousPermissions) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.app-dangerous-permissions",
		Title:           "GitHub Apps with organization-level power",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataAppInstallations},
		Description:     "Installed GitHub Apps that can change org settings, membership, secrets, runners, or workflow files.",
	}
}

func (c appDangerousPermissions) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, app := range s.AppInstallations {
		granted, reasons := dangerousPermissions(app.Permissions)
		if len(granted) == 0 {
			continue
		}
		// Blast radius, not bare capability: the same permission across every
		// repository is categorically worse than on a chosen few.
		sev := model.SevMedium
		scope := "the repositories it is installed on"
		if app.RepositorySelection == "all" {
			sev = model.SevHigh
			scope = "every repository in the organization"
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "GitHub App \"" + app.AppSlug + "\" can " + reasons[0],
			Severity: sev,
			Axis:     model.AxisNonHuman,
			Resource: appRef(app),
			Evidence: map[string]any{
				"app_slug":              app.AppSlug,
				"repository_selection":  app.RepositorySelection,
				"dangerous_permissions": granted,
			},
			Description: "This app holds permissions that reach past the code it was installed to work on, across " + scope + ": it can " + strings.Join(reasons, "; ") + ". " +
				"A compromise of the app or its publisher inherits all of it, and unlike a human credential there is no second factor in front of it.",
			Remediation: "Confirm this app needs that level of access and that its publisher is one you would trust with organization administration. If not, uninstall it. If so, narrow repository_selection to selected repositories and record the decision — an ignore rule with a reason keeps the acceptance visible.",
			DocsURL:     "https://docs.github.com/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
		})
	}
	return out
}

// dangerousPermissions returns the sorted "perm:level" pairs from the dangerous
// set that the app holds at write or admin, plus what each one enables.
func dangerousPermissions(perms map[string]string) (granted, reasons []string) {
	names := make([]string, 0, len(perms))
	for name := range perms {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if level := perms[name]; level == "write" || level == "admin" {
			// Read on these is metadata; control is what makes them dangerous.
			if why, dangerous := dangerousAppPermissions[name]; dangerous {
				granted = append(granted, name+":"+level)
				reasons = append(reasons, why)
			}
		}
	}
	return granted, reasons
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
