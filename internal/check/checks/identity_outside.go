package checks

import (
	"context"
	"strconv"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(outsideCollaborators{}) }

// outsideCollaborators surfaces non-member accounts that have repository access.
// These are sometimes legitimate (contractors, vendors) but each is access that
// lives outside the org's membership governance and deserves review.
type outsideCollaborators struct{}

func (outsideCollaborators) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.outside-collaborator",
		Title:           "Outside collaborators",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevLow,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataOutsideCollaborators},
		Description:     "Accounts with repo access that are not members of the organization.",
	}
}

func (c outsideCollaborators) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, cb := range s.OutsideCollabs {
		out = append(out, withFix(model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Outside collaborator has repository access",
			Severity: model.SevLow,
			Axis:     model.AxisIdentity,
			Resource: model.ResourceRef{
				Type: "member",
				ID:   strconv.FormatInt(cb.ID, 10),
				Name: cb.Login,
				URL:  "https://github.com/" + cb.Login,
			},
			Evidence:    map[string]any{"login": cb.Login, "is_bot": cb.IsBot},
			Description: "This account has access to one or more repositories without being part of the organization, so it falls outside membership-level controls such as 2FA enforcement and SSO.",
			Remediation: "Review whether this access is still needed; convert long-term collaborators to managed members or remove them.",
			DocsURL:     "https://docs.github.com/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/adding-outside-collaborators-to-repositories-in-your-organization",
		}, ghRemoveOutsideCollaborator(s.Org.Login, cb.Login)))
	}
	return out
}
