package collectgl

import (
	"context"
	"net/url"

	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// memberDTO is a GitLab group member as returned by the Members API.
type memberDTO struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	AccessLevel int    `json:"access_level"`
	State       string `json:"state"`
}

// fetchMembers lists the group's effective members, including those inherited
// from ancestor groups (the /members/all endpoint), and maps each member's
// access level onto the neutral org role: GitLab Owner (50) is the org owner
// (admin); everything below is a plain member.
func fetchMembers(ctx context.Context, client *glclient.Client, group string) ([]model.Member, error) {
	dtos, err := glclient.GetAll[memberDTO](ctx, client, "/groups/"+url.PathEscape(group)+"/members/all", nil)
	if err != nil {
		return nil, err
	}
	members := make([]model.Member, 0, len(dtos))
	for _, d := range dtos {
		role := "member"
		if model.RoleFromGitLabAccessLevel(d.AccessLevel) == model.RoleAdmin {
			role = "admin"
		}
		members = append(members, model.Member{
			Login: d.Username,
			ID:    d.ID,
			Role:  role,
		})
	}
	return members, nil
}
