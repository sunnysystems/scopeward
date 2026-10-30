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
// different axis. The evidence probe was verified against a live Team-plan org
// whose private repositories all have push protection enabled, and the billing
// probe against one that never bought it (see secretProtectionBilling).
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
	billing, err := fetchSecretProtectionBilling(ctx, client, org)
	snap.SetEntitlement(secretProtectionFromBilling(billing, err))
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

// secretProtectionBilling is what the billing endpoint reports for the product.
//
// Only three of its numbers are evidence. maximum_advanced_security_committers
// is deliberately not among them: it is the count of committers who *would*
// consume the product if it were enabled on every repository, not a purchase.
// Observed on a live Team-plan org that had never bought Secret Protection, the
// endpoint answered maximum=1 (its one active committer), total=0, no
// repositories and no purchased count; reading maximum as seats marked that org
// entitled and let every private repository through the #50 gate (#96).
type secretProtectionBilling struct {
	Purchased    int // seats bought up front; absent under metered billing
	InUse        int // distinct committers consuming it today
	Repositories int // repositories consuming it today
	Maximum      int // would-be consumption if enabled everywhere; never evidence
}

// secretProtectionFromBilling interprets the billing probe. A failed probe is
// Unknown, never Absent: Absent suppresses findings, and a 403 from a token
// without admin:org would otherwise silently hide real exposure.
//
// A probe that answers with nothing purchased and nothing in use is Absent,
// including for an org on metered billing that could turn the product on at
// will. Turning it on is the purchase, so the remediation is still an invoice,
// which is the case #50 withholds.
func secretProtectionFromBilling(b secretProtectionBilling, err error) model.EntitlementStatus {
	switch {
	case err != nil:
		return model.EntitlementStatus{
			Entitlement: model.EntSecretProtection,
			State:       model.EntitlementUnknown,
			Reason:      reasonFor(err, "reading GitHub Secret Protection billing"),
		}
	case b.Purchased > 0:
		return model.EntitlementStatus{
			Entitlement: model.EntSecretProtection,
			State:       model.EntitlementGranted,
			Reason:      fmt.Sprintf("%d GitHub Secret Protection seat(s) purchased", b.Purchased),
		}
	case b.InUse > 0 || b.Repositories > 0:
		return model.EntitlementStatus{
			Entitlement: model.EntSecretProtection,
			State:       model.EntitlementGranted,
			Reason: fmt.Sprintf("GitHub Secret Protection is in use: %d committer(s) across %d repository(ies)",
				b.InUse, b.Repositories),
		}
	default:
		return model.EntitlementStatus{
			Entitlement: model.EntSecretProtection,
			State:       model.EntitlementAbsent,
			Reason: fmt.Sprintf("billing reports no GitHub Secret Protection purchased or in use "+
				"(enabling it would bill %d active committer(s))", b.Maximum),
		}
	}
}

// fetchSecretProtectionBilling reads the org's Secret Protection usage. The
// endpoint is shared with Code Security and requires the product to be named,
// which is why the query parameter is not optional.
func fetchSecretProtectionBilling(ctx context.Context, client *ghclient.Client, org string) (secretProtectionBilling, error) {
	var dto struct {
		Purchased    int        `json:"purchased_advanced_security_committers"`
		Total        int        `json:"total_advanced_security_committers"`
		Maximum      int        `json:"maximum_advanced_security_committers"`
		Repositories []struct{} `json:"repositories"`
	}
	q := url.Values{"advanced_security_product": {"secret_protection"}}
	if _, err := client.Get(ctx, "/orgs/"+org+"/settings/billing/advanced-security", q, &dto); err != nil {
		return secretProtectionBilling{}, err
	}
	return secretProtectionBilling{
		Purchased:    dto.Purchased,
		InUse:        dto.Total,
		Repositories: len(dto.Repositories),
		Maximum:      dto.Maximum,
	}, nil
}
