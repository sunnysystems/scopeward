package collect

import (
	"regexp"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/model"
)

// agentSignature is the mark a coding agent leaves on a commit it helped write
// while a human account authored it. Exactly one matcher is set per entry.
//
// Every entry cites where the mark is described. A signature nobody documented
// is a guess, and a guessed signature turns the inventory into a rumour; an
// agent missing from this table is simply not counted, which the report states.
type agentSignature struct {
	agent string
	// coAuthorEmail matches a Co-authored-by trailer by its address. The display
	// name is ignored: Claude Code puts the model in it ("Claude Opus 5 (1M
	// context)"), and GitHub's squash merge rewrites the key's case.
	coAuthorEmail string
	// trailerKey/trailerValue match a "Key: Value" trailer exactly.
	trailerKey, trailerValue string
	// authorSuffix matches the end of the git author name.
	authorSuffix string
	source       string
}

var agentSignatures = []agentSignature{
	{agent: "Claude Code", coAuthorEmail: "noreply@anthropic.com", source: "https://code.claude.com/docs/en/settings"},
	{agent: "Cursor", coAuthorEmail: "cursoragent@cursor.com", source: "https://forum.cursor.com/t/co-author-added-without-consent-and-cant-be-turned-off/150096"},
	{agent: "Cursor", trailerKey: "made-with", trailerValue: "cursor", source: "https://cursor.com/docs/integrations/git"},
	{agent: "Aider", authorSuffix: "(aider)", source: "https://aider.chat/docs/git.html"},
}

var (
	trailerRe     = regexp.MustCompile(`^([A-Za-z0-9-]+):\s*(.+?)\s*$`)
	trailerAddrRe = regexp.MustCompile(`<([^>]+)>\s*$`)
)

// matchAgent names the coding agent whose mark a commit carries, or "" for none.
// Trailers are read from the message's last paragraph only, as git does, so a
// commit body that merely quotes a trailer (a changelog, this very feature's
// own PR description) is not mistaken for one.
func matchAgent(authorName, message string) string {
	for _, sig := range agentSignatures {
		if sig.authorSuffix != "" && strings.HasSuffix(strings.TrimSpace(authorName), sig.authorSuffix) {
			return sig.agent
		}
	}
	for _, line := range strings.Split(lastParagraph(message), "\n") {
		m := trailerRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		key, value := strings.ToLower(m[1]), m[2]
		for _, sig := range agentSignatures {
			switch {
			case sig.coAuthorEmail != "" && key == "co-authored-by":
				if a := trailerAddrRe.FindStringSubmatch(value); a != nil && strings.EqualFold(a[1], sig.coAuthorEmail) {
					return sig.agent
				}
			case sig.trailerKey != "" && key == sig.trailerKey && strings.EqualFold(value, sig.trailerValue):
				return sig.agent
			}
		}
	}
	return ""
}

// isAgentAddress reports whether an email is one an agent signs its commits
// with, rather than a person's.
func isAgentAddress(email string) bool {
	for _, sig := range agentSignatures {
		if sig.coAuthorEmail != "" && strings.EqualFold(strings.TrimSpace(email), sig.coAuthorEmail) {
			return true
		}
	}
	return false
}

// lastParagraph returns the final blank-line-separated block of a commit
// message, where git looks for trailers.
func lastParagraph(message string) string {
	message = strings.TrimRight(strings.ReplaceAll(message, "\r\n", "\n"), "\n \t")
	if i := strings.LastIndex(message, "\n\n"); i >= 0 {
		return message[i+2:]
	}
	return message
}

// commitDTO is the slice of a commit-list item the collector reads.
type commitDTO struct {
	Author *struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"author"`
	Commit struct {
		Author struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
		Message string `json:"message"`
	} `json:"commit"`
}

// tallyCommits splits recent commits into the two populations the AI axis
// reports: machine identities that authored commits themselves, and commits a
// human authored with a coding agent's mark. A bot's own commit is counted
// once, as the bot's, even when it also carries an agent trailer.
func tallyCommits(dtos []commitDTO) ([]model.CommitActivity, []model.AgentAssist) {
	bots := map[string]int{}
	type assistKey struct{ agent, author string }
	assists := map[assistKey]int{}
	for _, c := range dtos {
		login := ""
		if c.Author != nil {
			if isBotLogin(c.Author.Login, c.Author.Type) {
				bots[c.Author.Login]++
				continue
			}
			login = c.Author.Login
		}
		// An unlinked author (no GitHub account behind the email) still counts:
		// the agent's code reached the branch either way. So does a commit the
		// agent authored itself (a cloud session commits as the agent's own
		// address), but then the login names no person: GitHub links that address
		// to whichever account happens to claim it.
		if agent := matchAgent(c.Commit.Author.Name, c.Commit.Message); agent != "" {
			if isAgentAddress(c.Commit.Author.Email) {
				login = ""
			}
			assists[assistKey{agent, login}]++
		}
	}

	botOut := make([]model.CommitActivity, 0, len(bots))
	for login, n := range bots {
		botOut = append(botOut, model.CommitActivity{Login: login, Commits: n})
	}
	sort.Slice(botOut, func(i, j int) bool { return botOut[i].Login < botOut[j].Login })

	assistOut := make([]model.AgentAssist, 0, len(assists))
	for k, n := range assists {
		assistOut = append(assistOut, model.AgentAssist{Agent: k.agent, Author: k.author, Commits: n})
	}
	sort.Slice(assistOut, func(i, j int) bool {
		if assistOut[i].Agent != assistOut[j].Agent {
			return assistOut[i].Agent < assistOut[j].Agent
		}
		return assistOut[i].Author < assistOut[j].Author
	})
	return botOut, assistOut
}
