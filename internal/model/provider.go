package model

// Provider names the source forge a Snapshot was collected from. The model and
// checks are provider-neutral; the provider is recorded so renderers and
// provider-guarded checks can adapt, and so a report makes clear which forge it
// describes.
type Provider string

const (
	// ProviderGitHub is github.com or GitHub Enterprise.
	ProviderGitHub Provider = "github"
	// ProviderGitLab is gitlab.com or a self-managed GitLab instance.
	ProviderGitLab Provider = "gitlab"
)
