package collectgl

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/sunnysystems/scopeward/internal/model"
)

// defaultConcurrency bounds in-flight per-resource API calls (e.g. one per
// subgroup or project) to stay polite with GitLab's rate limits while still
// overlapping I/O. It mirrors the GitHub collector's value.
const defaultConcurrency = 8

// forEachIndex runs fn for each index in [0,n) with at most `limit` concurrent
// goroutines. fn handles its own errors (collectors record coverage rather than
// failing the run). It stops launching new work if ctx is cancelled.
func forEachIndex(ctx context.Context, limit, n int, fn func(ctx context.Context, i int)) {
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(ctx, i)
		}(i)
	}
	wg.Wait()
}

// covTally accumulates the outcome of a per-item collection (one DataKind across
// many subgroups/projects) so it reduces to a single Coverage entry. Safe for
// concurrent use.
type covTally struct {
	failed     atomic.Int64
	count      atomic.Int64
	reasonOnce sync.Once
	reason     string
}

func (t *covTally) add(n int) { t.count.Add(int64(n)) }

func (t *covTally) fail(reason string) {
	t.failed.Add(1)
	t.reasonOnce.Do(func() { t.reason = reason })
}

// record reduces the tally to coverage: fully OK, partial if some items failed,
// or missing if every attempt failed.
func (t *covTally) record(cov *model.CoverageReport, kind model.DataKind, attempted int) {
	failed := int(t.failed.Load())
	switch {
	case attempted == 0 || failed == 0:
		cov.OK(kind, int(t.count.Load()))
	case failed < attempted:
		cov.Partial(kind, int(t.count.Load()), "some items were unreadable: "+t.reason)
	default:
		cov.Missing(kind, t.reason)
	}
}
