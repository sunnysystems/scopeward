package collectgl

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// projectDTO is a GitLab project as returned by /groups/:id/projects.
type projectDTO struct {
	ID                int64      `json:"id"`
	PathWithNamespace string     `json:"path_with_namespace"`
	Visibility        string     `json:"visibility"` // private | internal | public
	Archived          bool       `json:"archived"`
	DefaultBranch     string     `json:"default_branch"`
	LastActivityAt    *time.Time `json:"last_activity_at"`
	Namespace         struct {
		FullPath string `json:"full_path"`
	} `json:"namespace"`
	SharedWithGroups []struct {
		GroupFullPath    string `json:"group_full_path"`
		GroupAccessLevel int    `json:"group_access_level"`
	} `json:"shared_with_groups"`
}

// collectProjects lists every project in the group tree as a neutral Repo, and
// attributes each project to the subgroup(s) that grant access to it (the team
// "RepoGrants"): the owning subgroup (access is by inheritance, so no explicit
// level) plus any group the project is explicitly shared with (at the share's
// access level). Grant presence is what the team-design checks read.
func collectProjects(ctx context.Context, client *glclient.Client, group string, snap *model.Snapshot) {
	dtos, err := glclient.GetAll[projectDTO](ctx, client, "/groups/"+url.PathEscape(group)+"/projects",
		url.Values{"include_subgroups": {"true"}, "with_shared": {"false"}})
	if err != nil {
		snap.Coverage.Missing(model.DataRepos, reasonFor(err, "listing projects"))
		snap.Coverage.Missing(model.DataTeamRepos, "projects could not be listed")
		snap.Coverage.Missing(model.DataRepoDirectCollaborators, "projects could not be listed")
		return
	}

	repos := make([]model.Repo, 0, len(dtos))
	for _, d := range dtos {
		repos = append(repos, model.Repo{
			Name:          d.PathWithNamespace,
			ID:            d.ID,
			Private:       d.Visibility != "public",
			Archived:      d.Archived,
			PushedAt:      d.LastActivityAt,
			DefaultBranch: d.DefaultBranch,
		})
	}
	snap.Repos = repos
	snap.Coverage.OK(model.DataRepos, len(repos))

	// Attribute projects to teams (subgroups) to build RepoGrants. Only possible
	// when the subgroup tree was listed.
	if !snap.Coverage.Available(model.DataTeams) {
		snap.Coverage.Missing(model.DataTeamRepos, "subgroups could not be listed")
		return
	}
	teamBySlug := make(map[string]*model.Team, len(snap.Teams))
	for i := range snap.Teams {
		teamBySlug[snap.Teams[i].Slug] = &snap.Teams[i]
	}
	grants := 0
	for _, d := range dtos {
		// Owning subgroup: members inherit access (no explicit grant level).
		if t := teamBySlug[d.Namespace.FullPath]; t != nil {
			t.RepoGrants = append(t.RepoGrants, model.TeamRepoGrant{Repo: d.PathWithNamespace})
			grants++
		}
		// Explicit shares onto a (sub)group, at the share's access level.
		for _, sh := range d.SharedWithGroups {
			if t := teamBySlug[sh.GroupFullPath]; t != nil {
				t.RepoGrants = append(t.RepoGrants, model.TeamRepoGrant{
					Repo:       d.PathWithNamespace,
					Permission: string(model.RoleFromGitLabAccessLevel(sh.GroupAccessLevel)),
				})
				grants++
			}
		}
	}
	snap.Coverage.OK(model.DataTeamRepos, grants)
}

// collectProjectMembers fills each (non-archived) project's directly-granted
// members in a bounded-concurrency pass, mapping the GitLab access level onto the
// neutral role scale so the direct-grant and over-privilege checks evaluate.
func collectProjectMembers(ctx context.Context, client *glclient.Client, snap *model.Snapshot) {
	if !snap.Coverage.Available(model.DataRepos) || len(snap.Repos) == 0 {
		snap.Coverage.Missing(model.DataRepoDirectCollaborators, "projects could not be listed")
		return
	}

	var targets []int
	for i := range snap.Repos {
		if !snap.Repos[i].Archived {
			targets = append(targets, i)
		}
	}
	sort.Slice(targets, func(a, b int) bool { return snap.Repos[targets[a]].Name < snap.Repos[targets[b]].Name })

	var grants covTally
	forEachIndex(ctx, defaultConcurrency, len(targets), func(ctx context.Context, t int) {
		r := &snap.Repos[targets[t]]
		dtos, err := glclient.GetAll[memberDTO](ctx, client, "/projects/"+strconv.FormatInt(r.ID, 10)+"/members", nil)
		if err != nil {
			grants.fail(reasonFor(err, "listing project members"))
			return
		}
		for _, d := range dtos {
			r.DirectCollaborators = append(r.DirectCollaborators, model.RepoGrant{
				Login:      d.Username,
				Permission: string(model.RoleFromGitLabAccessLevel(d.AccessLevel)),
			})
		}
		grants.add(len(dtos))
	})
	grants.record(snap.Coverage, model.DataRepoDirectCollaborators, len(targets))
}
