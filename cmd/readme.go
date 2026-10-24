package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

type readmeMod struct {
	ID          string
	Description string
}

type readmeGroup struct {
	Platform plugin.Platform
	Category plugin.Category
	Mods     []readmeMod
}

var readmePlatformOrder = []plugin.Platform{
	plugin.PlatformAWS,
	plugin.PlatformAzure,
	plugin.PlatformGCP,
	plugin.PlatformSaaS,
}

var readmeCategoryOrder = []plugin.Category{
	plugin.CategoryRecon,
	plugin.CategoryAnalyze,
	plugin.CategorySecrets,
}

var readmePlatformTitles = map[plugin.Platform]string{
	plugin.PlatformAWS:   "AWS",
	plugin.PlatformAzure: "Azure",
	plugin.PlatformGCP:   "GCP",
	plugin.PlatformSaaS:  "SaaS",
}

var readmeCategoryTitles = map[plugin.Category]string{
	plugin.CategoryRecon:   "Reconnaissance",
	plugin.CategoryAnalyze: "Analysis",
	plugin.CategorySecrets: "Secrets",
}

func updateREADME(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	modRaw, err := os.ReadFile("./go.mod")
	if err != nil {
		return err
	}
	goVersion, err := goVersionFromMod(string(modRaw))
	if err != nil {
		return err
	}
	updated, err := applyReadme(string(raw), collectReadmeModules(), goVersion)
	if err != nil {
		return err
	}
	if updated == string(raw) {
		return nil
	}
	if err := os.WriteFile(path, []byte(updated), 0644); err != nil {
		return err
	}
	fmt.Println("README.md module inventory updated")
	return nil
}

func applyReadme(content string, live []readmeGroup, goVersion string) (string, error) {
	existing, err := extractReadmeModules(content)
	if err != nil {
		return "", err
	}
	rendered := renderReadmeModuleTables(mergeReadmeModules(existing, live))
	content, err = replaceReadmeMarked(content, "modules", rendered)
	if err != nil {
		return "", err
	}
	counts := readmePlatformCounts(live)
	for _, p := range []plugin.Platform{plugin.PlatformAWS, plugin.PlatformAzure, plugin.PlatformGCP} {
		content, err = replaceReadmeMarkedInline(content, "count:"+string(p), strconv.Itoa(counts[p]))
		if err != nil {
			return "", err
		}
	}
	content, err = replaceReadmeMarkedInline(content, "go-version", goVersion)
	if err != nil {
		return "", err
	}
	return content, nil
}

func goVersionFromMod(content string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "go" {
			continue
		}
		parts := strings.Split(fields[1], ".")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("invalid go directive in go.mod")
		}
		return parts[0] + "." + parts[1], nil
	}
	return "", fmt.Errorf("missing go directive in go.mod")
}

func collectReadmeModules() []readmeGroup {
	hierarchy := plugin.GetHierarchy()
	var groups []readmeGroup
	for _, p := range orderedPlatforms(hierarchy) {
		cats := hierarchy[p]
		for _, c := range orderedCategories(cats) {
			var mods []readmeMod
			for _, id := range cats[c] {
				m, ok := plugin.Get(p, c, id)
				if !ok {
					continue
				}
				mods = append(mods, readmeMod{ID: m.ID(), Description: m.Description()})
			}
			if len(mods) == 0 {
				continue
			}
			groups = append(groups, readmeGroup{Platform: p, Category: c, Mods: mods})
		}
	}
	return groups
}

func extractReadmeModules(content string) ([]readmeGroup, error) {
	body, err := readmeMarkedBody(content, "modules")
	if err != nil {
		return nil, err
	}
	return parseReadmeModuleTables(body), nil
}

func parseReadmeModuleTables(body string) []readmeGroup {
	var groups []readmeGroup
	current := -1
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "### ") {
			p, c, ok := parseReadmeHeading(strings.TrimPrefix(line, "### "))
			if !ok {
				current = -1
				continue
			}
			groups = append(groups, readmeGroup{Platform: p, Category: c})
			current = len(groups) - 1
			continue
		}
		if current < 0 {
			continue
		}
		id, desc, ok := parseReadmeModuleRow(line)
		if !ok {
			continue
		}
		groups[current].Mods = append(groups[current].Mods, readmeMod{ID: id, Description: desc})
	}
	return groups
}

func mergeReadmeModules(existing, live []readmeGroup) []readmeGroup {
	existingByKey := make(map[string][]readmeMod, len(existing))
	for _, g := range existing {
		existingByKey[readmeGroupKey(g)] = g.Mods
	}
	out := make([]readmeGroup, 0, len(live))
	for _, g := range live {
		out = append(out, readmeGroup{
			Platform: g.Platform,
			Category: g.Category,
			Mods:     mergeReadmeMods(existingByKey[readmeGroupKey(g)], g.Mods),
		})
	}
	return out
}

func mergeReadmeMods(existing, live []readmeMod) []readmeMod {
	existingOrder := make(map[string]int, len(existing))
	for i, m := range existing {
		existingOrder[m.ID] = i
	}
	out := make([]readmeMod, 0, len(live))
	var added []readmeMod
	for _, m := range live {
		rm := readmeMod{ID: m.ID, Description: shortReadmeDescription(m.Description)}
		if _, ok := existingOrder[m.ID]; ok {
			out = append(out, rm)
		} else {
			added = append(added, rm)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].ID < added[j].ID })
	return append(out, added...)
}

func renderReadmeModuleTables(groups []readmeGroup) string {
	var b strings.Builder
	for _, g := range groups {
		if len(g.Mods) == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "### %s %s\n\n", readmePlatformTitle(g.Platform), readmeCategoryTitle(g.Category))
		b.WriteString("| Module | Description |\n")
		b.WriteString("|--------|-------------|\n")
		for _, m := range g.Mods {
			fmt.Fprintf(&b, "| `%s` | %s |\n", m.ID, m.Description)
		}
	}
	return strings.TrimSpace(b.String())
}

func shortReadmeDescription(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > 120 {
		truncated := string([]rune(s)[:120])
		if i := strings.LastIndex(truncated, " "); i > 0 {
			truncated = strings.TrimRightFunc(truncated[:i], unicode.IsSpace)
		}
		s = truncated + "..."
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

func replaceReadmeMarked(content, name, body string) (string, error) {
	return replaceReadmeMarkedMode(content, name, strings.TrimSpace(body), true)
}

func replaceReadmeMarkedInline(content, name, body string) (string, error) {
	return replaceReadmeMarkedMode(content, name, body, false)
}

func replaceReadmeMarkedMode(content, name, body string, block bool) (string, error) {
	begin, end, inner, err := readmeMarkedSpan(content, name)
	if err != nil {
		return "", err
	}
	replacement := begin + body + end
	if block {
		replacement = begin + "\n" + body + "\n" + end
	}
	start := strings.Index(content, begin)
	stop := start + len(begin) + len(inner) + len(end)
	return content[:start] + replacement + content[stop:], nil
}

func readmeMarkedBody(content, name string) (string, error) {
	_, _, body, err := readmeMarkedSpan(content, name)
	return body, err
}

func readmeMarkedSpan(content, name string) (begin, end, body string, err error) {
	begin, end = readmeMarkers(name)
	beginIdx := strings.Index(content, begin)
	if beginIdx < 0 {
		return "", "", "", fmt.Errorf("missing begin marker %s", begin)
	}
	rest := content[beginIdx+len(begin):]
	endIdx := strings.Index(rest, end)
	if endIdx < 0 {
		return "", "", "", fmt.Errorf("missing end marker %s", end)
	}
	return begin, end, rest[:endIdx], nil
}

func readmeMarkers(name string) (string, string) {
	return "<!-- autogen:" + name + " -->", "<!-- /autogen:" + name + " -->"
}

func readmePlatformCounts(mods []readmeGroup) map[plugin.Platform]int {
	counts := make(map[plugin.Platform]int)
	for _, g := range mods {
		counts[g.Platform] += len(g.Mods)
	}
	return counts
}

func readmeGroupKey(g readmeGroup) string {
	return string(g.Platform) + "/" + string(g.Category)
}

func parseReadmeHeading(title string) (plugin.Platform, plugin.Category, bool) {
	for p, pt := range readmePlatformTitles {
		for c, ct := range readmeCategoryTitles {
			if title == pt+" "+ct {
				return p, c, true
			}
		}
	}
	parts := strings.SplitN(title, " ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return plugin.Platform(strings.ToLower(parts[0])), plugin.Category(strings.ToLower(parts[1])), true
}

func parseReadmeModuleRow(line string) (id, desc string, ok bool) {
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(strings.TrimSpace(line), "|") {
		return "", "", false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|"))
	parts := strings.SplitN(inner, "|", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	idCell := strings.TrimSpace(parts[0])
	desc = strings.TrimSpace(parts[1])
	if len(idCell) < 2 || idCell[0] != '`' || idCell[len(idCell)-1] != '`' {
		return "", "", false
	}
	id = idCell[1 : len(idCell)-1]
	if id == "" {
		return "", "", false
	}
	return id, desc, true
}

func readmePlatformTitle(p plugin.Platform) string {
	if t, ok := readmePlatformTitles[p]; ok {
		return t
	}
	return titleReadmeToken(string(p))
}

func readmeCategoryTitle(c plugin.Category) string {
	if t, ok := readmeCategoryTitles[c]; ok {
		return t
	}
	return titleReadmeToken(string(c))
}

func titleReadmeToken(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func orderedPlatforms(m map[plugin.Platform]map[plugin.Category][]string) []plugin.Platform {
	seen := make(map[plugin.Platform]bool)
	var out []plugin.Platform
	for _, p := range readmePlatformOrder {
		if _, ok := m[p]; ok {
			out = append(out, p)
			seen[p] = true
		}
	}
	var extra []plugin.Platform
	for p := range m {
		if !seen[p] {
			extra = append(extra, p)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	return append(out, extra...)
}

func orderedCategories(m map[plugin.Category][]string) []plugin.Category {
	seen := make(map[plugin.Category]bool)
	var out []plugin.Category
	for _, c := range readmeCategoryOrder {
		if _, ok := m[c]; ok {
			out = append(out, c)
			seen[c] = true
		}
	}
	var extra []plugin.Category
	for c := range m {
		if !seen[c] {
			extra = append(extra, c)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	return append(out, extra...)
}
