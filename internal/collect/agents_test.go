package collect

import (
	"reflect"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestMatchAgent(t *testing.T) {
	cases := []struct {
		name, author, message, want string
	}{
		{
			name:    "claude code trailer, model in the display name",
			author:  "Alice",
			message: "fix: handle 409\n\nBody.\n\nCo-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>",
			want:    "Claude Code",
		},
		{
			name:    "squash merge lowercases the trailer key",
			author:  "Alice",
			message: "feat: x (#12)\n\n* one\n* two\n\nCo-authored-by: Claude <noreply@anthropic.com>\nCo-authored-by: Bob <bob@example.com>",
			want:    "Claude Code",
		},
		{
			name:    "cursor cloud agent co-author",
			author:  "Alice",
			message: "chore: bump\n\nCo-authored-by: Cursor <cursoragent@cursor.com>",
			want:    "Cursor",
		},
		{
			name:    "cursor made-with trailer",
			author:  "Alice",
			message: "chore: bump\n\nMade-with: Cursor",
			want:    "Cursor",
		},
		{
			name:    "aider marks the author name",
			author:  "Alice (aider)",
			message: "refactor: split parser",
			want:    "Aider",
		},
		{
			name:    "a quoted trailer mid-body is not a trailer",
			author:  "Alice",
			message: "docs: explain attribution\n\nAgents add\nCo-Authored-By: Claude <noreply@anthropic.com>\nto commits.\n\nSigned-off-by: Alice <alice@example.com>",
			want:    "",
		},
		{
			name:    "human co-author only",
			author:  "Alice",
			message: "pair on it\n\nCo-authored-by: Bob <bob@example.com>",
			want:    "",
		},
		{
			name:    "the agent's address in the name position does not count",
			author:  "Alice",
			message: "x\n\nCo-authored-by: noreply@anthropic.com <alice@example.com>",
			want:    "",
		},
		{
			name:    "CRLF line endings and trailing blank lines",
			author:  "Alice",
			message: "x\r\n\r\nCo-Authored-By: Claude <NOREPLY@anthropic.com>\r\n\r\n",
			want:    "Claude Code",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchAgent(tc.author, tc.message); got != tc.want {
				t.Errorf("matchAgent = %q, want %q", got, tc.want)
			}
		})
	}
}

// commit builds a commit-list item; login "" means the email is linked to no
// GitHub account, so the API returns a null author.
func commit(login, typ, authorName, message string) commitDTO {
	var c commitDTO
	if login != "" {
		c.Author = &struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		}{login, typ}
	}
	c.Commit.Author.Name = authorName
	c.Commit.Message = message
	return c
}

func withEmail(c commitDTO, email string) commitDTO {
	c.Commit.Author.Email = email
	return c
}

func TestTallyCommits(t *testing.T) {
	claude := "x\n\nCo-Authored-By: Claude <noreply@anthropic.com>"
	dtos := []commitDTO{
		commit("dependabot[bot]", "Bot", "dependabot[bot]", "bump"),
		commit("dependabot[bot]", "Bot", "dependabot[bot]", "bump"),
		// A bot commit with an agent trailer is the bot's, counted once.
		commit("claude[bot]", "Bot", "claude[bot]", claude),
		commit("alice", "User", "Alice", claude),
		commit("alice", "User", "Alice", claude),
		commit("bob", "User", "Bob (aider)", "refactor"),
		commit("", "", "Carol", claude), // unlinked author
		// A cloud session authors as the agent's own address, which GitHub links
		// to an unrelated account that claimed it: no person is named.
		withEmail(commit("claude", "User", "Claude", claude), "noreply@anthropic.com"),
		commit("dave", "User", "Dave", "plain human commit"),
	}
	bots, assists := tallyCommits(dtos)

	wantBots := []model.CommitActivity{{Login: "claude[bot]", Commits: 1}, {Login: "dependabot[bot]", Commits: 2}}
	if !reflect.DeepEqual(bots, wantBots) {
		t.Errorf("bots = %+v, want %+v", bots, wantBots)
	}
	wantAssists := []model.AgentAssist{
		{Agent: "Aider", Author: "bob", Commits: 1},
		{Agent: "Claude Code", Author: "", Commits: 2},
		{Agent: "Claude Code", Author: "alice", Commits: 2},
	}
	if !reflect.DeepEqual(assists, wantAssists) {
		t.Errorf("assists = %+v, want %+v", assists, wantAssists)
	}
}

// Every signature must say where it comes from: an entry with no source is a
// guess, and the table's whole claim is that it holds none.
func TestAgentSignaturesCiteASource(t *testing.T) {
	for _, sig := range agentSignatures {
		matchers := 0
		for _, set := range []bool{sig.coAuthorEmail != "", sig.trailerKey != "", sig.authorSuffix != ""} {
			if set {
				matchers++
			}
		}
		if sig.agent == "" || sig.source == "" || matchers != 1 {
			t.Errorf("signature %+v: want an agent, a source and exactly one matcher", sig)
		}
	}
}
