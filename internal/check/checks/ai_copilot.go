package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(copilotSeatInactive{})
	check.Register(copilotSeatNonMember{})
}

// copilotInactiveAfter is how long a Copilot seat can go without activity before
// it is considered inactive.
const copilotInactiveAfter = 90 * 24 * time.Hour

// copilotSeatInactive flags assigned Copilot seats that have never been used or
// have been idle for 90+ days — wasted spend and an AI capability granted to
// someone who is not exercising it (and may not need it).
type copilotSeatInactive struct{}

func (copilotSeatInactive) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.copilot-seat-inactive",
		Title:           "Inactive Copilot seats",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevLow,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataCopilotSeats},
		Description:     "Assigned Copilot seats never used or idle for over 90 days.",
	}
}

func (c copilotSeatInactive) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}
	var out []model.Finding
	for _, seat := range s.CopilotSeats {
		idle := seat.LastActivityAt == nil || now.Sub(*seat.LastActivityAt) > copilotInactiveAfter
		if !idle {
			continue
		}
		when := "never used"
		ev := map[string]any{"login": seat.Login}
		if seat.LastActivityAt != nil {
			days := int(now.Sub(*seat.LastActivityAt).Hours() / 24)
			when = fmt.Sprintf("idle %d days", days)
			ev["days_idle"] = days
		} else {
			ev["never_used"] = true
		}
		out = append(out, withFix(model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Copilot seat for " + seat.Login + " is inactive (" + when + ")",
			Severity:    model.SevLow,
			Axis:        model.AxisAIAgents,
			Resource:    model.ResourceRef{Type: "member", Name: seat.Login, URL: "https://github.com/" + seat.Login},
			Evidence:    ev,
			Description: "This Copilot seat is assigned but not being used. It is recurring spend, and it is AI code-generation access granted to an account that is not exercising it; access that should be intentional, not leftover.",
			Remediation: "Reclaim seats that are no longer needed; confirm the assignment is still intentional for the rest.",
			DocsURL:     "https://docs.github.com/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-access-to-github-copilot-in-your-organization/revoking-access-to-github-copilot-for-members-of-your-organization",
		}, ghRemoveCopilotSeat(s.Org.Login, seat.Login)))
	}
	return out
}

// copilotSeatNonMember flags Copilot seats assigned to logins that are not org
// members — AI access held by someone outside the org's membership governance.
type copilotSeatNonMember struct{}

func (copilotSeatNonMember) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.copilot-seat-non-member",
		Title:           "Copilot seats for non-members",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataCopilotSeats, model.DataMembers},
		Description:     "Copilot seats assigned to accounts that are not organization members.",
	}
}

func (c copilotSeatNonMember) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	members := make(map[string]bool, len(s.Members))
	for _, m := range s.Members {
		members[m.Login] = true
	}
	var out []model.Finding
	for _, seat := range s.CopilotSeats {
		if seat.Login == "" || members[seat.Login] {
			continue
		}
		out = append(out, withFix(model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Copilot seat assigned to non-member " + seat.Login,
			Severity:    model.SevMedium,
			Axis:        model.AxisAIAgents,
			Resource:    model.ResourceRef{Type: "member", Name: seat.Login, URL: "https://github.com/" + seat.Login},
			Evidence:    map[string]any{"login": seat.Login},
			Description: "This account holds a Copilot seat but is not a member of the organization, so its AI access sits outside membership-based reviews and offboarding. It may be a former member whose seat was never reclaimed.",
			Remediation: "Revoke the seat, or add the account as a governed member if the access is intended.",
			DocsURL:     "https://docs.github.com/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-access-to-github-copilot-in-your-organization",
		}, ghRemoveCopilotSeat(s.Org.Login, seat.Login)))
	}
	return out
}
