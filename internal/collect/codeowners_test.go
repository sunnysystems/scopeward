package collect

import (
	"reflect"
	"testing"
)

func TestParseCodeownersTeams(t *testing.T) {
	content := `# Default owners
*           @acme/platform @alice
# A comment with a fake @acme/ghost mention is still parsed only on content lines
/docs/      @acme/docs-team
/legacy/    @bob bob@example.com
*.tf        @acme/platform
`
	got := parseCodeownersTeams(content)
	want := []string{"@acme/platform", "@acme/docs-team"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("teams = %v, want %v", got, want)
	}
}

func TestParseCodeownersTeams_skipsComments(t *testing.T) {
	content := "# @acme/not-a-real-owner\n*  @alice\n"
	if got := parseCodeownersTeams(content); len(got) != 0 {
		t.Errorf("got %v, want none (only an individual and a comment)", got)
	}
}
