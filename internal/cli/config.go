package cli

import (
	"strings"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
)

// defaultStaleAfterDays is used when --stale-after-days is unset or non-positive.
const defaultStaleAfterDays = 365

// defaultOwningTeamProperty is the custom-property name the ownership check looks
// for when --owning-team-property is unset.
const defaultOwningTeamProperty = "owning-team"

// configureAudit applies run-time audit configuration (not collected from the
// API) onto the snapshot and records its coverage, so config-dependent checks
// degrade to "not evaluated" when the config is absent.
func configureAudit(snap *model.Snapshot, opts *options) {
	domains := normalizeDomains(opts.companyDomains)
	snap.CompanyDomains = domains
	if len(domains) > 0 {
		snap.Coverage.OK(model.DataCompanyDomains, len(domains))
	} else {
		snap.Coverage.Missing(model.DataCompanyDomains, "no --company-domain provided")
	}

	days := opts.staleAfterDays
	if days <= 0 {
		days = defaultStaleAfterDays
	}
	snap.StaleAfter = time.Duration(days) * 24 * time.Hour

	prop := strings.ToLower(strings.TrimSpace(opts.owningTeamProperty))
	if prop == "" {
		prop = defaultOwningTeamProperty
	}
	snap.OwningTeamProperty = prop

	// Out-of-range values fall back to the check default rather than erroring: a
	// similarity above 1 can never match and one at or below 0 would pair every
	// team with every other, and silently doing either would be worse than
	// ignoring the flag.
	if sim := opts.duplicateSimilarity; sim > 0 && sim <= 1 {
		snap.DuplicateRosterSimilarity = sim
	}

	snap.Solo = opts.solo
	// The org's declared policy. Checks read it for threshold overrides and
	// invariants; nil simply means every check keeps its product default.
	snap.Policy = opts.policy
}

// normalizeDomains lowercases each domain and strips a leading "@", dropping
// blanks. So "@MyCompany.com" and "mycompany.com" both become "mycompany.com".
func normalizeDomains(in []string) []string {
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "@")
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}
