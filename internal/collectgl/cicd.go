package collectgl

import (
	"context"
	"strconv"
	"sync"

	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// collectCICD gathers GitLab's CI/CD hardening surface: project and group CI/CD
// variables, runners (with their protected-ref enforcement), and each project's
// CI_JOB_TOKEN inbound allowlist. These map GitHub's Actions secrets / runners /
// GITHUB_TOKEN concerns onto GitLab's model.
//
// The whole pass fans out per group and per project, so it is skipped in --quick
// mode (group-level audit only). GitHub Actions concepts (the usage policy, the
// GITHUB_TOKEN default, org Actions secrets, GitHub-style self-hosted runners)
// are recorded as coverage gaps so their checks report "not evaluated".
func collectCICD(ctx context.Context, client *glclient.Client, snap *model.Snapshot, opts collect.Options) {
	snap.Coverage.Missing(model.DataActionsPolicy, "GitLab has no GitHub-Actions usage policy; CI/CD is configured per project")
	snap.Coverage.Missing(model.DataActionsTokenDefault, "GitLab has no GITHUB_TOKEN default; the CI_JOB_TOKEN allowlist is collected as job-token scope")
	snap.Coverage.Missing(model.DataSelfHostedRunners, "GitLab runners are collected as CI runners (shared/group/project), not GitHub self-hosted runners")
	snap.Coverage.Missing(model.DataOrgSecrets, "GitLab has no org Actions secrets; CI/CD variables are collected separately")

	if opts.Quick {
		for _, k := range []model.DataKind{model.DataCIVariables, model.DataCIRunners, model.DataJobTokenScope} {
			snap.Coverage.Missing(k, "skipped in --quick mode (group-level audit only)")
		}
		return
	}

	collectCIVariables(ctx, client, snap)
	collectCIRunners(ctx, client, snap)
	collectJobTokenScope(ctx, client, snap)
}

// collectCIVariables fills snap.CIVariables from the group tree's and each
// project's CI/CD variables. The variable's value is never requested or stored —
// only the protection flags and environment scope the checks read.
func collectCIVariables(ctx context.Context, client *glclient.Client, snap *model.Snapshot) {
	type varScope struct {
		resource string // "groups" | "projects"
		kind     string // "group" | "project"
		id       int64
		path     string
	}
	scopes := []varScope{{"groups", "group", snap.Org.ID, snap.Org.Login}}
	for _, t := range snap.Teams {
		scopes = append(scopes, varScope{"groups", "group", t.ID, t.Slug})
	}
	for _, r := range snap.Repos {
		scopes = append(scopes, varScope{"projects", "project", r.ID, r.Name})
	}

	var (
		mu    sync.Mutex
		tally covTally
	)
	forEachIndex(ctx, defaultConcurrency, len(scopes), func(ctx context.Context, i int) {
		sc := scopes[i]
		dtos, err := glclient.GetAll[glVariableDTO](ctx, client, "/"+sc.resource+"/"+strconv.FormatInt(sc.id, 10)+"/variables", nil)
		if err != nil {
			tally.fail(reasonFor(err, "listing CI/CD variables"))
			return
		}
		vars := make([]model.CIVariable, 0, len(dtos))
		for _, d := range dtos {
			vars = append(vars, d.toModel(sc.kind, sc.path, sc.id))
		}
		mu.Lock()
		snap.CIVariables = append(snap.CIVariables, vars...)
		mu.Unlock()
		tally.add(len(dtos))
	})
	tally.record(snap.Coverage, model.DataCIVariables, len(scopes))
}

// collectCIRunners lists the runners visible to the group and each project, then
// reads each unique runner's detail for its protected-ref enforcement and lock
// state (the list endpoint omits access_level). Listing and detail failures both
// degrade the coverage rather than aborting.
func collectCIRunners(ctx context.Context, client *glclient.Client, snap *model.Snapshot) {
	type runnerScope struct {
		resource string
		id       int64
		path     string
	}
	scopes := []runnerScope{{"groups", snap.Org.ID, snap.Org.Login}}
	for _, t := range snap.Teams {
		scopes = append(scopes, runnerScope{"groups", t.ID, t.Slug})
	}
	for _, r := range snap.Repos {
		scopes = append(scopes, runnerScope{"projects", r.ID, r.Name})
	}

	var (
		mu     sync.Mutex
		holder = map[int64]string{} // runner id -> path of the scope that first surfaced it
		tally  covTally
	)
	forEachIndex(ctx, defaultConcurrency, len(scopes), func(ctx context.Context, i int) {
		sc := scopes[i]
		dtos, err := glclient.GetAll[glRunnerListDTO](ctx, client, "/"+sc.resource+"/"+strconv.FormatInt(sc.id, 10)+"/runners", nil)
		if err != nil {
			tally.fail(reasonFor(err, "listing CI runners"))
			return
		}
		mu.Lock()
		for _, d := range dtos {
			if _, seen := holder[d.ID]; !seen {
				holder[d.ID] = sc.path
			}
		}
		mu.Unlock()
	})

	ids := make([]int64, 0, len(holder))
	for id := range holder {
		ids = append(ids, id)
	}
	runners := make([]model.CIRunner, len(ids))
	forEachIndex(ctx, defaultConcurrency, len(ids), func(ctx context.Context, i int) {
		var d glRunnerDetailDTO
		if _, err := client.Get(ctx, "/runners/"+strconv.FormatInt(ids[i], 10), nil, &d); err != nil {
			tally.fail(reasonFor(err, "reading CI runner detail"))
			return
		}
		runners[i] = d.toModel(holder[ids[i]])
		tally.add(1)
	})
	for _, r := range runners {
		if r.ID != 0 {
			snap.CIRunners = append(snap.CIRunners, r)
		}
	}
	tally.record(snap.Coverage, model.DataCIRunners, len(scopes)+len(ids))
}

// collectJobTokenScope reads each project's CI_JOB_TOKEN inbound allowlist
// setting. inbound_enabled=false means any project's job token may access this
// project, which is the GitLab analogue of a default-write CI token.
func collectJobTokenScope(ctx context.Context, client *glclient.Client, snap *model.Snapshot) {
	if !snap.Coverage.Available(model.DataRepos) || len(snap.Repos) == 0 {
		snap.Coverage.Missing(model.DataJobTokenScope, "projects could not be listed")
		return
	}
	var tally covTally
	forEachIndex(ctx, defaultConcurrency, len(snap.Repos), func(ctx context.Context, i int) {
		r := &snap.Repos[i]
		var d glJobTokenScopeDTO
		if _, err := client.Get(ctx, "/projects/"+strconv.FormatInt(r.ID, 10)+"/job_token_scope", nil, &d); err != nil {
			tally.fail(reasonFor(err, "reading CI_JOB_TOKEN scope"))
			return
		}
		enabled := d.InboundEnabled
		r.JobTokenInboundEnabled = &enabled
		tally.add(1)
	})
	tally.record(snap.Coverage, model.DataJobTokenScope, len(snap.Repos))
}

// --- DTOs ---

// glVariableDTO is a GitLab CI/CD variable. The "value" field is deliberately
// omitted so the secret is never read into memory.
type glVariableDTO struct {
	Key              string `json:"key"`
	VariableType     string `json:"variable_type"`
	Protected        bool   `json:"protected"`
	Masked           bool   `json:"masked"`
	Hidden           bool   `json:"hidden"`
	EnvironmentScope string `json:"environment_scope"`
}

func (d glVariableDTO) toModel(kind, holder string, scopeID int64) model.CIVariable {
	return model.CIVariable{
		Key:              d.Key,
		Kind:             kind,
		Holder:           holder,
		ScopeID:          scopeID,
		VariableType:     d.VariableType,
		Protected:        d.Protected,
		Masked:           d.Masked,
		Hidden:           d.Hidden,
		EnvironmentScope: d.EnvironmentScope,
	}
}

// glRunnerListDTO is the listing shape; only the id is used to drive the detail
// fetch that carries access_level.
type glRunnerListDTO struct {
	ID int64 `json:"id"`
}

// glRunnerDetailDTO is a runner's detail (GET /runners/:id), which carries the
// access_level the list endpoint omits.
type glRunnerDetailDTO struct {
	ID          int64    `json:"id"`
	Description string   `json:"description"`
	RunnerType  string   `json:"runner_type"`  // instance_type | group_type | project_type
	AccessLevel string   `json:"access_level"` // ref_protected | not_protected
	Locked      bool     `json:"locked"`
	Online      *bool    `json:"online"`
	TagList     []string `json:"tag_list"`
}

func (d glRunnerDetailDTO) toModel(holder string) model.CIRunner {
	shared := d.RunnerType == "instance_type"
	if shared {
		holder = "" // instance runners are not owned by one group/project
	}
	return model.CIRunner{
		ID:           d.ID,
		Description:  d.Description,
		RunnerType:   d.RunnerType,
		Shared:       shared,
		RefProtected: d.AccessLevel == "ref_protected",
		Locked:       d.Locked,
		Online:       d.Online,
		TagList:      d.TagList,
		Holder:       holder,
	}
}

// glJobTokenScopeDTO is the project CI_JOB_TOKEN inbound-allowlist setting.
type glJobTokenScopeDTO struct {
	InboundEnabled bool `json:"inbound_enabled"`
}
