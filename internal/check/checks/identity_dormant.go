package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(dormantMember{}) }

// dormantAfter is how long a member can go without any activity before being
// flagged as dormant.
const dormantAfter = 90 * 24 * time.Hour

// dormantMember flags members with no recent activity, where the provider
// exposes a last-activity signal (GitLab last_activity_on). Dormant accounts are
// prime offboarding misses: a stale credential or session is a low-noise way in.
//
// The check is provider-neutral and gates on DataMemberActivity coverage, so it
// is simply skipped on providers (or tokens) that cannot see last-activity —
// never a false pass.
type dormantMember struct{}

func (dormantMember) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.dormant-member",
		Title:           "Dormant members",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevLow,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataMembers, model.DataMemberActivity},
		Description:     "Members with no activity for an extended period (where the provider exposes last-activity data).",
	}
}

func (c dormantMember) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}
	// The org's declared window when it set one: 90 days is a product opinion,
	// and the right default, but an org that decided otherwise should be
	// measured against its own decision.
	window := s.DormantAfter(dormantAfter)

	var out []model.Finding
	for _, m := range s.Members {
		if m.LastActiveAt == nil || now.Sub(*m.LastActiveAt) <= window {
			continue // unknown activity, or active recently enough
		}
		days := int(now.Sub(*m.LastActiveAt).Hours() / 24)
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Member %s has been inactive for %d days", m.Login, days),
			Severity:    model.SevLow,
			Axis:        model.AxisIdentity,
			Resource:    model.ResourceRef{Type: "member", Name: m.Login},
			Evidence:    map[string]any{"login": m.Login, "last_active_at": m.LastActiveAt.Format("2006-01-02"), "inactive_days": days},
			Description: "This account has shown no activity for a long time. Dormant accounts are easy to forget during offboarding and widen the attack surface — a leftover credential or session is a quiet way in.",
			Remediation: "Confirm the account is still needed; if not, remove the member. For contractors and leavers, revoke access promptly.",
		})
	}
	return out
}
