// Package model holds the domain types: the immutable Snapshot collected from
// GitHub, the Finding emitted by checks, and the CoverageReport that records
// what could not be seen so the audit degrades honestly.
package model

// Axis groups checks and findings by the governance dimension they cover.
type Axis string

const (
	AxisIdentity     Axis = "identity"      // human identity: 2FA, SSO, outside collaborators, dormancy
	AxisTeams        Axis = "teams"         // teams & permissions: sprawl, nesting, over-privilege
	AxisNonHuman     Axis = "nonhuman"      // apps, OAuth, PATs, deploy keys, webhooks, secrets, runners
	AxisAIAgents     Axis = "ai_agents"     // governance of machine/bot identities committing code
	AxisHygiene      Axis = "hygiene"       // repository hygiene: stale/abandoned repos and their lingering access
	AxisCodeSecurity Axis = "code_security" // code-protection features: secret scanning, push protection, dependabot
	AxisSupplyChain  Axis = "supply_chain"  // CI/CD supply chain: unpinned actions, dangerous workflow triggers
)

// Title returns a human-readable label for the axis.
func (a Axis) Title() string {
	switch a {
	case AxisIdentity:
		return "Human Identity"
	case AxisTeams:
		return "Teams & Permissions"
	case AxisNonHuman:
		return "Non-Human Identities"
	case AxisAIAgents:
		return "AI Agents"
	case AxisHygiene:
		return "Repository Hygiene"
	case AxisCodeSecurity:
		return "Code Security"
	case AxisSupplyChain:
		return "Supply Chain"
	default:
		return string(a)
	}
}
