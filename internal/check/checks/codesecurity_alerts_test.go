package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// Archiving a repository does not un-leak a credential already in its history.
// The check must keep firing on archived repos — it is the one exemption to the
// activeRepos guard — and say something different, because the remediation is to
// rotate the credential, never to fix or re-archive the repository.
func TestOpenSecretAlerts_ArchivedRepo(t *testing.T) {
	three, two := 3, 2
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "live", OpenSecretAlerts: &three},
		{Name: "retired", Archived: true, OpenSecretAlerts: &two},
		{Name: "clean", Archived: true, OpenSecretAlerts: new(int)},
	}

	got := openSecretAlerts{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (live + retired; the clean archived repo is silent)", len(got))
	}
	byRepo := map[string]model.Finding{}
	for _, f := range got {
		byRepo[f.Evidence["repo"].(string)] = f
	}

	retired := byRepo["retired"]
	if retired.Severity != model.SevHigh {
		t.Errorf("archived severity = %v, want high: archiving does not reduce the exposure", retired.Severity)
	}
	if retired.Evidence["archived"] != true {
		t.Error("evidence should record that the repo is archived")
	}
	if !strings.Contains(retired.Title, "Archived") {
		t.Errorf("title %q should say the repository is archived", retired.Title)
	}
	if !strings.Contains(retired.Remediation, "not a mitigation") {
		t.Errorf("remediation %q should say archiving is not a mitigation", retired.Remediation)
	}

	// The live repo keeps the original wording.
	if strings.Contains(byRepo["live"].Title, "Archived") {
		t.Errorf("live repo got archived wording: %q", byRepo["live"].Title)
	}
}
