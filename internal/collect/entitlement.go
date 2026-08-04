package collect

import (
	"context"
	"fmt"
	"net/url"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// detectSecretProtection establishes whether the org can enable secret scanning
// and push protection on its *private* repositories.
//
// The plan name deliberately plays no part in this. GitHub sells Secret
// Protection as a metered product independent of the plan tier, so a Team org
// may hold it and an Enterprise org may not — gating on plan.name would suppress
// findings the org can actually act on, which is the same false negative in a
// different axis. Verified against a live Team-plan org whose private
// repositories all have push protection enabled.
//
// Two probes, cheapest first:
//
//  1. Evidence. A private repository with push protection already enabled is
//     proof by demonstration: the org holds the entitlement, and it cost no API
//     call because the snapshot already carries the state.
//
//  2. Billing. Only when the evidence is silent, ask what the org purchased.
//     This costs one request and needs admin:org, so it never runs for an org
//     that has already proven the point.
//
// Anything else is Unknown, which checks treat as "report as before" — see
// model.EntitlementState.
// The two probes are kept as pure functions and composed here, so the decision
// logic is testable without standing up an HTTP server — the same split the
// package doc draws between doing I/O and deciding what it means.
func detectSecretProtection(ctx context.Context, client *ghclient.Client, org string, snap *model.Snapshot) {
	if st := secretProtectionFromEvidence(snap); st != nil {
		snap.SetEntitlement(*st)
		return
	}
	// No private repository proves it either way. That is the case where the
	// entitlement genuinely decides whether hundreds of findings are actionable,
	// so it is worth one request to answer it.
	seats, err := fetchSecretProtectionSeats(ctx, client, org)
	snap.SetEntitlement(secretProtectionFromSeats(seats, err))
}

// secretProtectionFromEvidence answers from repository state alone, or returns
// nil when the state cannot settle it. Only a positive answer is possible here:
// push protection being on somewhere proves the entitlement, but it being off
// everywhere is equally consistent with an org that holds it and never enabled
// it, so absence of evidence must fall through to the billing probe.
func secretProtectionFromEvidence(snap *model.Snapshot) *model.EntitlementStatus {
	n := 0
	for _, r := range snap.Repos {
		// Archived repos count: the setting could only have been turned on while
		// the repo was writable, which is the same proof.
		if r.Private && r.PushProtection != nil && *r.PushProtection {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return &model.EntitlementStatus{
		Entitlement: model.EntSecretProtection,
		State:       model.EntitlementGranted,
		Reason: fmt.Sprintf("push protection is enabled on %d private repository(ies), which is only possible with it",
			n),
	}
}

// secretProtectionFromSeats interprets the billing probe. A failed probe is
// Unknown, never Absent: Absent suppresses findings, and a 403 from a token
// without admin:org would otherwise silently hide real exposure.
func secretProtectionFromSeats(seats int, err error) model.EntitlementStatus {
	switch {
	case err != nil:
		return model.EntitlementStatus{
			Entitlement: model.EntSecretProtection,
			State:       model.EntitlementUnknown,
			Reason:      reasonFor(err, "reading GitHub Secret Protection billing"),
		}
	case seats > 0:
		return model.EntitlementStatus{
			Entitlement: model.EntSecretProtection,
			State:       model.EntitlementGranted,
			Reason:      fmt.Sprintf("%d GitHub Secret Protection seat(s) provisioned", seats),
		}
	default:
		return model.EntitlementStatus{
			Entitlement: model.EntSecretProtection,
			State:       model.EntitlementAbsent,
			Reason:      "no GitHub Secret Protection seats are provisioned for this organization",
		}
	}
}

// fetchSecretProtectionSeats returns how many Secret Protection committer seats
// the org has available. The endpoint is shared with Code Security and requires
// the product to be named, which is why the query parameter is not optional.
func fetchSecretProtectionSeats(ctx context.Context, client *ghclient.Client, org string) (int, error) {
	var dto struct {
		MaximumCommitters int `json:"maximum_advanced_security_committers"`
		TotalCommitters   int `json:"total_advanced_security_committers"`
	}
	q := url.Values{"advanced_security_product": {"secret_protection"}}
	if _, err := client.Get(ctx, "/orgs/"+org+"/settings/billing/advanced-security", q, &dto); err != nil {
		return 0, err
	}
	// Either number being positive means the product is provisioned: maximum is
	// what was purchased, total is what is in use. They can disagree while a
	// purchase is being drawn down, and one of them being zero is not evidence.
	if dto.MaximumCommitters > dto.TotalCommitters {
		return dto.MaximumCommitters, nil
	}
	return dto.TotalCommitters, nil
}
