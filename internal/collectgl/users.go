package collectgl

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// userEnrichWorkers bounds the concurrent per-member /users/:id lookups so a
// large group does not open a goroutine (and request) per member at once.
const userEnrichWorkers = 8

// userDetailDTO is the admin-visible portion of a GitLab user. two_factor_enabled
// and last_activity_on are returned only to instance admins; for anyone else they
// are absent (nil), which is how we detect that the data is not visible.
type userDetailDTO struct {
	TwoFactorEnabled *bool   `json:"two_factor_enabled"`
	LastActivityOn   *string `json:"last_activity_on"` // date-only "2006-01-02"
}

func (d userDetailDTO) lastActive() *time.Time {
	if d.LastActivityOn == nil || *d.LastActivityOn == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", *d.LastActivityOn)
	if err != nil {
		return nil
	}
	return &t
}

// enrichMembers fills per-member 2FA state and last activity. GitLab exposes both
// only to instance admins, so a non-admin token (e.g. a gitlab.com group owner)
// leaves DataMember2FA and DataMemberActivity uncollected — the dependent checks
// then report "not evaluated" rather than a false pass.
func enrichMembers(ctx context.Context, client *glclient.Client, snap *model.Snapshot) {
	admin, err := isInstanceAdmin(ctx, client)
	if err != nil {
		reason := reasonFor(err, "checking instance-admin privileges")
		snap.Coverage.Missing(model.DataMember2FA, reason)
		snap.Coverage.Missing(model.DataMemberActivity, reason)
		return
	}
	if !admin {
		const reason = "per-member 2FA and last-activity require an instance-admin token; GitLab does not expose them to group owners"
		snap.Coverage.Missing(model.DataMember2FA, reason)
		snap.Coverage.Missing(model.DataMemberActivity, reason)
		return
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed int
		sem    = make(chan struct{}, userEnrichWorkers)
	)
	for i := range snap.Members {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			d, err := fetchUserDetail(ctx, client, snap.Members[i].ID)
			if err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			// Distinct slice indices → safe to write without a lock.
			snap.Members[i].TwoFactorEnabled = d.TwoFactorEnabled
			snap.Members[i].LastActiveAt = d.lastActive()
		}()
	}
	wg.Wait()

	if failed == 0 {
		snap.Coverage.OK(model.DataMember2FA, len(snap.Members))
		snap.Coverage.OK(model.DataMemberActivity, len(snap.Members))
		return
	}
	reason := strconv.Itoa(failed) + " of " + strconv.Itoa(len(snap.Members)) + " member lookups failed"
	snap.Coverage.Partial(model.DataMember2FA, len(snap.Members)-failed, reason)
	snap.Coverage.Partial(model.DataMemberActivity, len(snap.Members)-failed, reason)
}

// isInstanceAdmin reports whether the authenticated user is a GitLab instance
// admin, which determines whether per-member 2FA/activity is visible.
func isInstanceAdmin(ctx context.Context, client *glclient.Client) (bool, error) {
	var u struct {
		IsAdmin bool `json:"is_admin"`
	}
	if _, err := client.Get(ctx, "/user", nil, &u); err != nil {
		return false, err
	}
	return u.IsAdmin, nil
}

func fetchUserDetail(ctx context.Context, client *glclient.Client, id int64) (userDetailDTO, error) {
	var d userDetailDTO
	_, err := client.Get(ctx, "/users/"+strconv.FormatInt(id, 10), nil, &d)
	return d, err
}
