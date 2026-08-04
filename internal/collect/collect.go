// Package collect performs the concurrent, read-only GitHub API calls that fill
// a model.Snapshot. Collection is kept separate from evaluation: collectors do
// all the I/O and record coverage; checks (a later package) are pure functions
// over the resulting snapshot.
package collect

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// Now is the clock used to stamp the snapshot; overridable in tests.
var Now = time.Now

// Reporter receives progress updates during collection so a caller can show the
// user what is happening on a long run. All methods may be called concurrently.
type Reporter interface {
	// Stage announces a new phase of work (e.g. "scanning repositories").
	Stage(msg string)
	// SetRepoProgress reports how many repositories have been scanned so far.
	SetRepoProgress(done, total int)
}

// noopReporter is used when the caller passes no Reporter.
type noopReporter struct{}

func (noopReporter) Stage(string)             {}
func (noopReporter) SetRepoProgress(int, int) {}

// Options tunes how much collection does, to trade depth for speed/budget.
type Options struct {
	Quick    bool     // skip the per-repo pass entirely (org-level checks only)
	MaxRepos int      // cap how many repos the per-repo pass scans (0 = no cap)
	Repos    []string // audit only repos matching one of these globs (empty = all)
}

// perRepoKinds are the DataKinds produced only by the per-repo pass; used to mark
// them not-collected when --quick skips that pass.
var perRepoKinds = []model.DataKind{
	model.DataRepoDirectCollaborators, model.DataDeployKeys, model.DataRepoWebhooks,
	model.DataCommitAuthors, model.DataBranchProtection, model.DataRepoSecurity,
	model.DataOpenSecretAlerts, model.DataDependabotEnabled, model.DataOpenDependabotAlerts,
	model.DataWorkflows, model.DataCodeowners,
}

// Run collects everything scopeward currently knows how to gather for an org and
// returns the assembled snapshot. A hard failure (org not accessible) returns an
// error; everything finer-grained is recorded as a coverage gap so the audit
// degrades honestly instead of aborting. prog may be nil.
func Run(ctx context.Context, client *ghclient.Client, org string, prog Reporter, opts Options) (*model.Snapshot, error) {
	if prog == nil {
		prog = noopReporter{}
	}
	snap := model.NewSnapshot(org)

	prog.Stage("resolving organization " + org)
	adminVisible, err := collectOrg(ctx, client, org, snap)
	if err != nil {
		return nil, fmt.Errorf("cannot read organization %q: %w", org, err)
	}

	// The axes touch disjoint snapshot fields and a thread-safe coverage report,
	// so they collect concurrently.
	prog.Stage("collecting members, teams & repositories")
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		collectHumanIdentity(ctx, client, org, snap, adminVisible)
	}()
	go func() {
		defer wg.Done()
		collectTeamsAndPermissions(ctx, client, org, snap, prog, opts)
	}()
	go func() {
		defer wg.Done()
		collectNonHuman(ctx, client, org, snap)
	}()
	wg.Wait()

	// A --repo filter that selects nothing is a typo (or the wrong org): fail
	// loudly rather than render a clean audit of zero repositories.
	if len(opts.Repos) > 0 && snap.Coverage.Available(model.DataRepos) && len(snap.Repos) == 0 {
		return nil, fmt.Errorf("no repository in %q matched --repo %s", org, strings.Join(opts.Repos, ", "))
	}

	// Entitlements are probed last: the cheap evidence path reads the repository
	// state the pass above just collected. --quick skips the per-repo pass, so
	// there is no evidence to read and no check that would consume the answer —
	// probing there would spend a request to inform nobody.
	if !opts.Quick {
		prog.Stage("checking entitlements")
		detectSecretProtection(ctx, client, org, snap)
	}

	snap.CollectedAt = Now()
	return snap, nil
}

// collectHumanIdentity lists members (the spine of this axis) then enriches them
// concurrently with 2FA, role, SAML, and outside-collaborator data.
func collectHumanIdentity(ctx context.Context, client *ghclient.Client, org string, snap *model.Snapshot, adminVisible bool) {
	members, err := fetchMembers(ctx, client, org)
	if err != nil {
		snap.Coverage.Missing(model.DataMembers, reasonFor(err, "listing members"))
		return
	}
	snap.Members = members
	snap.Coverage.OK(model.DataMembers, len(members))

	var (
		wg            sync.WaitGroup
		noTwoFA       map[string]bool
		owners        map[string]bool
		samlLinked    map[string]string
		outsideCollab []model.Collaborator
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		// The 2fa_disabled filter is only trustworthy for org owners; a
		// non-owner token silently gets the full list, which would falsely flag
		// everyone. We trust it only when org-admin fields were visible.
		if !adminVisible {
			snap.Coverage.Missing(model.DataMember2FA, "requires an organization owner token")
			return
		}
		logins, err := fetchLogins(ctx, client, org, "filter", "2fa_disabled")
		if err != nil {
			snap.Coverage.Missing(model.DataMember2FA, reasonFor(err, "listing 2FA-disabled members"))
			return
		}
		noTwoFA = logins
		snap.Coverage.OK(model.DataMember2FA, len(logins))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		logins, err := fetchLogins(ctx, client, org, "role", "admin")
		if err != nil {
			snap.Coverage.Missing(model.DataMemberRoles, reasonFor(err, "listing org owners"))
			return
		}
		owners = logins
		snap.Coverage.OK(model.DataMemberRoles, len(logins))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		linked, err := fetchSAMLIdentities(ctx, client, org)
		if err != nil {
			snap.Coverage.Missing(model.DataSAMLIdentities, reasonFor(err, "reading SAML identities"))
			return
		}
		samlLinked = linked
		snap.Coverage.OK(model.DataSAMLIdentities, len(linked))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		collabs, err := fetchOutsideCollaborators(ctx, client, org)
		if err != nil {
			snap.Coverage.Missing(model.DataOutsideCollaborators, reasonFor(err, "listing outside collaborators"))
			return
		}
		outsideCollab = collabs
		snap.Coverage.OK(model.DataOutsideCollaborators, len(collabs))
	}()

	wg.Wait()

	applyEnrichment(snap, noTwoFA, owners, samlLinked)
	snap.OutsideCollabs = outsideCollab
}

// applyEnrichment folds the concurrently-collected flag sets into the member
// list. A nil set means that data was not collected, so the corresponding
// pointer flag stays nil (unknown) rather than being set to a false value.
func applyEnrichment(snap *model.Snapshot, noTwoFA, owners map[string]bool, samlNameIDs map[string]string) {
	for i := range snap.Members {
		m := &snap.Members[i]
		if noTwoFA != nil {
			enabled := !noTwoFA[m.Login]
			m.TwoFactorEnabled = &enabled
		}
		if owners != nil {
			if owners[m.Login] {
				m.Role = "admin"
			} else {
				m.Role = "member"
			}
		}
		if samlNameIDs != nil {
			nameID, linked := samlNameIDs[m.Login]
			m.SAMLLinked = &linked
			m.SAMLNameID = nameID
		}
	}
}

// reasonFor turns an API error into a short human reason for a coverage gap. It
// distinguishes 403 (a real permission gap) from 404 (the feature is not
// available for this org/plan, or the resource is absent) and surfaces GitHub's
// own message, which usually says precisely why — instead of a blanket
// "insufficient scope" that misleads owners whose token is actually fine.
func reasonFor(err error, action string) string {
	msg := ghclient.Message(err)
	switch ghclient.StatusCode(err) {
	case http.StatusForbidden:
		const hint = "check token scope, owner role, or SSO authorization"
		if msg != "" {
			return fmt.Sprintf("%s: forbidden, %s (%s)", action, msg, hint)
		}
		return fmt.Sprintf("%s: forbidden (%s)", action, hint)
	case http.StatusNotFound:
		const hint = "feature may not be enabled for this org/plan, or the resource is absent"
		if msg != "" {
			return fmt.Sprintf("%s: not available, %s (%s)", action, msg, hint)
		}
		return fmt.Sprintf("%s: not available (%s)", action, hint)
	}
	return fmt.Sprintf("%s: %v", action, err)
}
