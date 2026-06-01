package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(ownerSprawl{}) }

const (
	// ownerCountThreshold is the absolute number of owners above which we flag,
	// and ownerRatioThreshold the share of members, whichever triggers first.
	ownerCountThreshold = 5
	ownerRatioThreshold = 0.10
	// ownerRatioMinMembers stops the ratio rule from flagging tiny orgs, where a
	// couple of owners is expected (e.g. 2 owners on a 3-person team).
	ownerRatioMinMembers = 10
	// ownerTitleCap is how many owner logins to name inline before summarizing.
	ownerTitleCap = 10
)

// ownerSprawl flags an excess of organization owners. Owner is the most
// privileged role; every owner is a full-org blast radius if compromised.
type ownerSprawl struct{}

func (ownerSprawl) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.owner-sprawl",
		Title:           "Too many org owners",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataMembers, model.DataMemberRoles},
		Description:     "An unusually high number of org owners widens the most privileged blast radius.",
	}
}

func (c ownerSprawl) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	owners := s.Owners()
	n := len(owners)
	total := len(s.Members)
	if n == 0 {
		return nil
	}

	overCount := n > ownerCountThreshold
	overRatio := total >= ownerRatioMinMembers && float64(n)/float64(total) > ownerRatioThreshold
	if !overCount && !overRatio {
		return nil
	}

	logins := make([]string, 0, n)
	for _, o := range owners {
		logins = append(logins, o.Login)
	}

	return []model.Finding{{
		CheckID:     c.Meta().ID,
		Title:       fmt.Sprintf("Organization has %d owners: %s", n, summarizeLogins(logins)),
		Severity:    model.SevMedium,
		Axis:        model.AxisIdentity,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"owner_count": n, "member_count": total, "owners": logins},
		Description: "Owners have unrestricted control of the organization. A large owner set increases the chance that one compromised or careless account can damage every repository and setting.",
		Remediation: "Reduce owners to the minimum that operations require; move others to the least privilege they actually need.",
		DocsURL:     "https://docs.github.com/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization",
	}}
}

// summarizeLogins joins logins for display, capping the inline list so the title
// stays readable on large owner sets (the full list is always in evidence).
func summarizeLogins(logins []string) string {
	if len(logins) <= ownerTitleCap {
		return strings.Join(logins, ", ")
	}
	return fmt.Sprintf("%s … +%d more", strings.Join(logins[:ownerTitleCap], ", "), len(logins)-ownerTitleCap)
}
