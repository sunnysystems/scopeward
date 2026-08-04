package checks

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(tokenNoExpiry{})
	check.Register(tokenBroadScope{})
	check.Register(tokenStale{})
	check.Register(deployTokenNoExpiry{})
}

// tokenStaleWindow is how long an active token can go unused (or sit unused
// since creation) before it is treated as abandoned.
const tokenStaleWindow = 90 * 24 * time.Hour

// broadTokenScopes are GitLab access-token scopes that grant wide, coarse
// access, mapped to the severity a token carrying them warrants. "api" is full
// read-write API access; "sudo"/"admin_mode" are instance-admin powers.
var broadTokenScopes = map[string]model.Severity{
	"api":              model.SevHigh,
	"sudo":             model.SevHigh,
	"admin_mode":       model.SevHigh,
	"write_repository": model.SevMedium,
	"write_registry":   model.SevMedium,
	"create_runner":    model.SevMedium,
	"k8s_proxy":        model.SevMedium,
}

// tokenLabel describes a token for a finding title: "personal access token
// ci-pat (alice)" or "project access token deploy (acme/api)".
func tokenLabel(tk model.AccessToken) string {
	kind := tk.Kind
	if kind == "" {
		kind = "access"
	}
	label := kind + " access token"
	if tk.Name != "" {
		label += " " + tk.Name
	}
	if tk.Holder != "" {
		label += " (" + tk.Holder + ")"
	}
	return label
}

// tokenResource builds a neutral ResourceRef for an access token. Tokens have no
// stable web URL, so the holder/scope identifiers ride in the ID and evidence so
// a later fixer can build the revoke path.
func tokenResource(tk model.AccessToken) model.ResourceRef {
	return model.ResourceRef{Type: "access_token", ID: strconv.FormatInt(tk.ID, 10), Name: tk.Holder}
}

func tokenEvidence(tk model.AccessToken) map[string]any {
	ev := map[string]any{"kind": tk.Kind, "holder": tk.Holder, "token_id": tk.ID, "scopes": tk.Scopes}
	if tk.ScopeID != 0 {
		ev["scope_id"] = tk.ScopeID
	}
	if tk.LastUsedAt != nil {
		ev["last_used_at"] = tk.LastUsedAt.Format(time.RFC3339)
	}
	return ev
}

// live reports whether a token is a current, usable credential (not revoked or
// already inactive/expired) — only those are worth flagging.
func live(tk model.AccessToken) bool { return tk.Active && !tk.Revoked }

const accessTokenDocs = "https://docs.gitlab.com/ee/security/token_overview.html"

// tokenNoExpiry flags active access tokens that never expire. A non-expiring
// token is a standing credential that stays valid long after the need (or the
// person) that created it is gone.
type tokenNoExpiry struct{}

func (tokenNoExpiry) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.token-no-expiry",
		Title:           "Non-expiring access tokens",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataAccessTokens},
		Description:     "Personal, project, or group access tokens that are active and have no expiration.",
	}
}

func (c tokenNoExpiry) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, tk := range s.AccessTokens {
		if !live(tk) || tk.ExpiresAt != nil {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Non-expiring " + tokenLabel(tk),
			Severity:    model.SevMedium,
			Axis:        model.AxisNonHuman,
			Resource:    tokenResource(tk),
			Evidence:    tokenEvidence(tk),
			Description: "This access token is active and has no expiry, so it stays a valid credential indefinitely, including after the owner changes roles or leaves. Leaked or forgotten, it is durable access no one is watching.",
			Remediation: "Reissue the token with a bounded lifetime, and set a maximum token lifetime at the group or instance level so non-expiring tokens cannot be created.",
			DocsURL:     accessTokenDocs,
		})
	}
	return out
}

// tokenBroadScope flags active access tokens carrying coarse, wide-blast-radius
// scopes (notably "api", full read-write API access).
type tokenBroadScope struct{}

func (tokenBroadScope) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.token-broad-scope",
		Title:           "Broadly-scoped access tokens",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevHigh,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataAccessTokens},
		Description:     "Access tokens holding broad scopes such as api (full read-write) or sudo.",
	}
}

func (c tokenBroadScope) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, tk := range s.AccessTokens {
		if !live(tk) {
			continue
		}
		var broad []string
		sev := model.SevInfo
		for _, sc := range tk.Scopes {
			if bs, ok := broadTokenScopes[sc]; ok {
				broad = append(broad, sc)
				if bs > sev {
					sev = bs
				}
			}
		}
		if len(broad) == 0 {
			continue
		}
		ev := tokenEvidence(tk)
		ev["broad_scopes"] = broad
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       tokenLabel(tk) + " has broad scopes (" + strings.Join(broad, ", ") + ")",
			Severity:    sev,
			Axis:        model.AxisNonHuman,
			Resource:    tokenResource(tk),
			Evidence:    ev,
			Description: "This token's scopes grant wide, coarse access: a scope like \"api\" allows full read-write to everything the token's identity can reach. A broad machine credential is a large blast radius if it leaks.",
			Remediation: "Reissue the token with the narrowest scopes the automation actually needs (e.g. read_repository instead of api), and prefer a short lifetime.",
			DocsURL:     accessTokenDocs,
		})
	}
	return out
}

// tokenStale flags active access tokens that have not been used in a long time
// (or were created long ago and never used) — likely abandoned credentials that
// remain valid and unwatched.
type tokenStale struct{}

func (tokenStale) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.token-stale",
		Title:           "Stale access tokens",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevLow,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataAccessTokens},
		Description:     "Active access tokens unused for over 90 days, or created long ago and never used.",
	}
}

func (c tokenStale) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}

	var out []model.Finding
	for _, tk := range s.AccessTokens {
		if !live(tk) {
			continue
		}
		neverUsed := tk.LastUsedAt == nil
		ref := tk.LastUsedAt
		if neverUsed {
			ref = tk.CreatedAt
		}
		if ref == nil {
			continue // no last-used and no created timestamp: age unknown
		}
		age := now.Sub(*ref)
		if age < tokenStaleWindow {
			continue
		}

		days := int(age.Hours() / 24)
		sev := model.SevLow
		title := tokenLabel(tk) + " unused for " + strconv.Itoa(days) + " days"
		if neverUsed {
			sev = model.SevMedium
			title = tokenLabel(tk) + " has never been used (created " + ref.Format("2006-01-02") + ")"
		}
		ev := tokenEvidence(tk)
		ev["never_used"] = neverUsed
		ev["idle_days"] = days
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       title,
			Severity:    sev,
			Axis:        model.AxisNonHuman,
			Resource:    tokenResource(tk),
			Evidence:    ev,
			Description: "This token is still active but has sat unused. A live credential that nobody uses is one nobody is watching either: it keeps its access and its blast radius while serving no purpose.",
			Remediation: "Confirm the token is still needed; if not, revoke it. If it is, rotate it and set a bounded lifetime so it is renewed deliberately.",
			DocsURL:     accessTokenDocs,
		})
	}
	return out
}

// deployTokenNoExpiry flags GitLab deploy tokens with no expiration. Deploy
// tokens are project/group automation credentials (a username plus repository or
// registry scopes); a non-expiring one is a standing, shared password.
type deployTokenNoExpiry struct{}

func (deployTokenNoExpiry) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.deploy-token-no-expiry",
		Title:           "Non-expiring deploy tokens",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataDeployTokens},
		Description:     "Deploy tokens (project or group automation credentials) that have no expiration.",
	}
}

func (c deployTokenNoExpiry) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, dt := range s.DeployTokens {
		if dt.Revoked || dt.ExpiresAt != nil {
			continue
		}
		label := dt.Kind + " deploy token \"" + dt.Name + "\""
		if dt.Holder != "" {
			label += " on " + dt.Holder
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Non-expiring " + label,
			Severity: model.SevMedium,
			Axis:     model.AxisNonHuman,
			Resource: model.ResourceRef{Type: "deploy_token", ID: strconv.FormatInt(dt.ID, 10), Name: dt.Holder},
			Evidence: map[string]any{
				"kind": dt.Kind, "holder": dt.Holder, "token_id": dt.ID,
				"scope_id": dt.ScopeID, "username": dt.Username, "scopes": dt.Scopes,
			},
			Description: "This deploy token never expires. Deploy tokens are shared, owner-less credentials used by CI and registries; a non-expiring one stays valid forever and is rarely rotated, so a leak is durable access that is hard to attribute.",
			Remediation: "Recreate the deploy token with an expiration and the minimum scopes needed, and revoke the non-expiring one.",
			DocsURL:     "https://docs.gitlab.com/ee/user/project/deploy_tokens/",
		})
	}
	return out
}
