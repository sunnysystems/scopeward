package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"

	"github.com/sunnysystems/scopeward/internal/access"
	"github.com/sunnysystems/scopeward/internal/accessview"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/ui"
)

// tab is which half of the TUI is showing: the findings, or the access graph
// they are findings about.
type tab int

const (
	tabFindings tab = iota
	tabAccess
)

// pivot is which side of the access graph the list walks.
type pivot int

const (
	pivotMembers pivot = iota
	pivotRepos
)

// memberItem is a person in the Access tab's member list.
type memberItem struct {
	v   access.MemberView
	top access.Level
}

func (i memberItem) Title() string {
	title := ui.Accent.Render(i.v.Login)
	if i.v.Outside {
		title += ui.Subtle.Render("  outside collaborator")
	}
	return title
}

func (i memberItem) Description() string {
	if len(i.v.OrgWide) > 0 && i.v.OrgWide[0].Kind == access.SourceOwner {
		return "   owner · admin everywhere"
	}
	return fmt.Sprintf("   %d repositories · up to %s", len(i.v.Repos), i.top)
}

func (i memberItem) FilterValue() string { return i.v.Login }

// repoItem is a repository in the Access tab's repository list.
type repoItem struct {
	v       access.RepoView
	writers int
}

func (i repoItem) Title() string { return ui.Accent.Render(i.v.Repo) }

func (i repoItem) Description() string {
	d := fmt.Sprintf("   %d with a specific grant · %d can write", len(i.v.People), i.writers)
	if i.v.Public {
		d += " · public"
	}
	if i.v.Archived {
		d += " · archived"
	}
	return d
}

func (i repoItem) FilterValue() string { return i.v.Repo }

// accessItems lists members or repositories, depending on the pivot.
func (m *appModel) accessItems() []list.Item {
	if m.graph == nil {
		return nil
	}
	opts := access.Options{IncludeArchived: m.showArchived}
	var items []list.Item
	if m.pivot == pivotMembers {
		for _, login := range m.graph.Members() {
			v, _ := m.graph.ForMember(login, opts)
			top := access.None
			if len(v.OrgWide) > 0 {
				top = v.OrgWide[0].Level
			}
			for _, a := range v.Repos {
				top = max(top, a.Effective)
			}
			items = append(items, memberItem{v: v, top: top})
		}
		return items
	}
	for _, name := range m.graph.Repos(opts) {
		v, _ := m.graph.ForRepo(name)
		writers := 0
		for _, a := range v.People {
			if a.Effective >= access.Write {
				writers++
			}
		}
		items = append(items, repoItem{v: v, writers: writers})
	}
	return items
}

// refreshAccessList rebuilds the access list after a pivot or archive toggle.
func (m *appModel) refreshAccessList() {
	m.accessList.ResetFilter()
	items := m.accessItems()
	m.accessList.SetItems(items)
	if m.pivot == pivotMembers {
		m.accessList.Title = fmt.Sprintf("Members (%d)", len(items))
	} else {
		m.accessList.Title = fmt.Sprintf("Repositories (%d)", len(items))
	}
	m.accessList.Select(0)
}

// accessDetail renders the selected member or repository the way
// `scopeward access` does.
func (m *appModel) accessDetail() string {
	var b strings.Builder
	switch v := m.accessList.SelectedItem().(type) {
	case memberItem:
		b.WriteString(ui.Title.Render(v.v.Login) + "\n\n")
		accessview.Member(&b, v.v, m.graph.Gaps(), accessview.MemberOptions{IncludeArchived: m.showArchived, ArchivedHint: "press x"})
	case repoItem:
		b.WriteString(ui.Title.Render(m.result.Snapshot.Org.Login+"/"+v.v.Repo) + "\n\n")
		accessview.Repo(&b, v.v, m.graph.Gaps())
	default:
		what := "members"
		if m.pivot == pivotRepos {
			what = "repositories"
		}
		b.WriteString(ui.Subtle.Render("Nothing to show: no " + what + " were collected."))
	}
	return b.String()
}

// openAccessFor jumps from a finding to the access view of what it is about:
// a repository or a person. It reports false when the finding is about
// neither, or about something the graph does not know.
func (m *appModel) openAccessFor(res model.ResourceRef) bool {
	if m.graph == nil {
		return false
	}
	var want string
	switch res.Type {
	case "repo":
		name := res.Name[strings.LastIndex(res.Name, "/")+1:]
		v, ok := m.graph.ForRepo(name)
		if !ok {
			return false
		}
		if v.Archived {
			m.showArchived = true
		}
		m.pivot, want = pivotRepos, name
	case "member":
		if _, ok := m.graph.ForMember(res.Name, access.Options{}); !ok {
			return false
		}
		m.pivot, want = pivotMembers, res.Name
	default:
		return false
	}
	m.refreshAccessList()
	for i, it := range m.accessList.Items() {
		if it.FilterValue() == want {
			m.accessList.Select(i)
			break
		}
	}
	m.tab = tabAccess
	return true
}

// selectedFinding is the finding under the cursor in the findings list: a
// leaf, or a group with exactly one finding in it.
func (m *appModel) selectedFinding() (model.Finding, bool) {
	switch v := m.list.SelectedItem().(type) {
	case findingItem:
		return v.f, true
	case groupItem:
		if len(v.g.findings) == 1 {
			return v.g.findings[0], true
		}
	}
	return model.Finding{}, false
}
