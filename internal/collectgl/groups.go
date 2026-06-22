package collectgl

import (
	"context"
	"net/url"
	"strconv"

	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// subgroupDTO is a descendant group as returned by /groups/:id/descendant_groups.
type subgroupDTO struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
	ParentID int64  `json:"parent_id"`
}

// fetchSubgroups walks the full subgroup tree under the top-level group and maps
// it onto the neutral Team model. The top-level group stays the Org (not a Team);
// a subgroup directly under it is a top-level team (empty ParentSlug), and a
// deeper subgroup records its parent subgroup's full path — so the neutral
// nesting/depth checks work unchanged.
func fetchSubgroups(ctx context.Context, client *glclient.Client, group string, topGroupID int64) ([]model.Team, error) {
	dtos, err := glclient.GetAll[subgroupDTO](ctx, client, "/groups/"+url.PathEscape(group)+"/descendant_groups", nil)
	if err != nil {
		return nil, err
	}
	idToPath := make(map[int64]string, len(dtos))
	for _, d := range dtos {
		idToPath[d.ID] = d.FullPath
	}
	teams := make([]model.Team, 0, len(dtos))
	for _, d := range dtos {
		parent := ""
		if d.ParentID != topGroupID {
			parent = idToPath[d.ParentID] // a nested subgroup's parent subgroup
		}
		teams = append(teams, model.Team{
			Slug:       d.FullPath,
			Name:       d.Name,
			ID:         d.ID,
			ParentSlug: parent,
		})
	}
	return teams, nil
}

// collectSubgroupMembers fills each subgroup's members and maintainers in a
// bounded-concurrency pass. GitLab Maintainer (40) and Owner (50) can manage the
// group's membership, so both map to the neutral "maintainer" role the orphan-team
// check looks for. Each goroutine writes a distinct Team, so no locking is needed.
func collectSubgroupMembers(ctx context.Context, client *glclient.Client, snap *model.Snapshot) {
	if !snap.Coverage.Available(model.DataTeams) || len(snap.Teams) == 0 {
		snap.Coverage.Missing(model.DataTeamMembers, "subgroups could not be listed")
		return
	}

	var members covTally
	forEachIndex(ctx, defaultConcurrency, len(snap.Teams), func(ctx context.Context, i int) {
		t := &snap.Teams[i]
		dtos, err := glclient.GetAll[memberDTO](ctx, client, "/groups/"+strconv.FormatInt(t.ID, 10)+"/members", nil)
		if err != nil {
			members.fail(reasonFor(err, "listing subgroup members"))
			return
		}
		for _, d := range dtos {
			t.Members = append(t.Members, d.Username)
			if d.AccessLevel >= model.GitLabMaintainer {
				t.Maintainers = append(t.Maintainers, d.Username)
			}
		}
		members.add(len(dtos))
	})
	members.record(snap.Coverage, model.DataTeamMembers, len(snap.Teams))
}
