package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(staleInvitation{}) }

// staleInvitationAge is how long an org invitation can sit unaccepted before we
// flag it.
const staleInvitationAge = 30 * 24 * time.Hour

// staleInvitation flags organization invitations that have been pending for a
// long time — usually forgotten invites that widen the set of people who could
// still gain access.
type staleInvitation struct{}

func (staleInvitation) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.stale-invitation",
		Title:           "Stale pending invitations",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevLow,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataPendingInvitations},
		Description:     "Organization invitations left unaccepted for over a month.",
	}
}

func (c staleInvitation) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}

	var out []model.Finding
	for _, inv := range s.PendingInvitations {
		if inv.CreatedAt == nil || now.Sub(*inv.CreatedAt) < staleInvitationAge {
			continue
		}
		who := inv.Login
		if who == "" {
			who = inv.Email
		}
		days := int(now.Sub(*inv.CreatedAt).Hours() / 24)
		f := model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Invitation for %s has been pending %d days", who, days),
			Severity:    model.SevLow,
			Axis:        model.AxisIdentity,
			Resource:    model.ResourceRef{Type: "invitation", Name: who},
			Evidence:    map[string]any{"invitee": who, "role": inv.Role, "days_pending": days},
			Description: "A long-pending invitation is access waiting to be claimed by an account you may no longer intend to add. It also signals onboarding that was never completed or cleaned up.",
			Remediation: "Cancel invitations that are no longer needed; re-send the few that are still intended.",
			DocsURL:     "https://docs.github.com/organizations/managing-membership-in-your-organization/canceling-or-editing-an-invitation-to-join-your-organization",
		}
		if inv.ID != 0 {
			f = withFix(f, ghCancelInvitation(s.Org.Login, inv.ID))
		}
		out = append(out, f)
	}
	return out
}
