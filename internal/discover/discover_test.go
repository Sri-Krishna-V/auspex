package discover

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
	"github.com/klauspost/compress/zstd"
)

func TestWalkFindsJSONLRecursively(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "projects", "a", "s1.jsonl"), "{}")
	mkfile(t, filepath.Join(root, "projects", "b", "s2.JSONL"), "{}") // case-insensitive ext
	mkfile(t, filepath.Join(root, "projects", "a", "notes.txt"), "x") // ignored
	mkfile(t, filepath.Join(root, "README.md"), "x")                  // ignored

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	if len(arts) != 2 {
		t.Fatalf("got %d artifacts, want 2: %+v", len(arts), arts)
	}
	for _, a := range arts {
		if a.Agent != model.AgentClaudeCode {
			t.Errorf("artifact %q agent = %q, want %q", a.Path, a.Agent, model.AgentClaudeCode)
		}
	}
	// Sorted by path for a deterministic scan order.
	if !(arts[0].Path < arts[1].Path) {
		t.Errorf("artifacts not in sorted order: %q then %q", arts[0].Path, arts[1].Path)
	}
}

func TestWalkSingleFile(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "session.jsonl")
	mkfile(t, f, "{}")

	arts, _, err := Walk(f)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || arts[0].Path != f || arts[0].Agent != model.AgentClaudeCode {
		t.Fatalf("got %+v, want one claude artifact at %q", arts, f)
	}
}

func TestWalkSingleNonArtifactFile(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "notes.txt")
	mkfile(t, f, "x")

	arts, _, err := Walk(f)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 0 {
		t.Fatalf("got %d artifacts, want 0", len(arts))
	}
}

func TestWalkMissingRootErrors(t *testing.T) {
	_, _, err := Walk(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("expected error for a missing root")
	}
}

func TestWalkEmptyDir(t *testing.T) {
	arts, _, err := Walk(t.TempDir())
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 0 {
		t.Fatalf("got %d artifacts, want 0", len(arts))
	}
}

// A symlinked directory root must be resolved and descended: os.Stat follows
// the link (reporting a dir) but filepath.WalkDir treats the link as a leaf, so
// without resolution the scan would silently find nothing.
func TestWalkSymlinkedDirRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	real := t.TempDir()
	mkfile(t, filepath.Join(real, "proj", "s.jsonl"), "{}")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	arts, _, err := Walk(link)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || filepath.Base(arts[0].Path) != "s.jsonl" {
		t.Fatalf("got %+v, want the artifact reached through the symlinked root", arts)
	}
}

func TestWalkSymlinkedCodexRootKeepsLogicalClassification(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	store := t.TempDir()
	mkfile(t, filepath.Join(store, "2026", "rollout.jsonl"), "{}")
	home := t.TempDir()
	root := filepath.Join(home, ".codex", "sessions")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(store, root); err != nil {
		t.Fatal(err)
	}

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 || len(arts) != 1 {
		t.Fatalf("artifacts=%+v skips=%+v, want one artifact and no skips", arts, skips)
	}
	if arts[0].Agent != model.AgentCodex {
		t.Fatalf("agent = %q, want %q", arts[0].Agent, model.AgentCodex)
	}
	wantPath := filepath.Join(root, "2026", "rollout.jsonl")
	if arts[0].Path != wantPath {
		t.Fatalf("path = %q, want logical path %q", arts[0].Path, wantPath)
	}
}

func TestArtifactDedupeKeyMatchesPhysicalFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	root := t.TempDir()
	file := filepath.Join(root, "session.jsonl")
	mkfile(t, file, "{}")
	link := filepath.Join(t.TempDir(), "alias.jsonl")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}

	direct, _, err := Walk(file)
	if err != nil {
		t.Fatal(err)
	}
	alias, _, err := Walk(link)
	if err != nil {
		t.Fatal(err)
	}
	if direct[0].DedupeKey() != alias[0].DedupeKey() {
		t.Fatalf("dedupe keys differ: %q vs %q", direct[0].DedupeKey(), alias[0].DedupeKey())
	}
}

// A symlinked .jsonl file under a directory root is classified and returned
// when its resolved target stays inside that root.
func TestWalkSymlinkedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	root := t.TempDir()
	targetDir := filepath.Join(root, "targets")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetDir, "target.txt")
	mkfile(t, target, "{}")
	link := filepath.Join(root, "session.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	arts, _, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	// The root is resolved before walking (so a symlinked root is descended),
	// which means arts[0].Path may be the resolved form of the directory. Match
	// on the file name rather than the literal root, since some platforms (e.g.
	// macOS /var -> /private/var) resolve the temp dir to a different prefix.
	if len(arts) != 1 || filepath.Base(arts[0].Path) != "session.jsonl" {
		t.Fatalf("got %+v, want the symlinked .jsonl named session.jsonl", arts)
	}
}

func TestOpenArtifactPinsValidatedSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	root := t.TempDir()
	inside := filepath.Join(root, "inside.txt")
	mkfile(t, inside, "inside")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	mkfile(t, outside, "outside")
	link := filepath.Join(root, "session.jsonl")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	arts, _, err := Walk(root)
	if err != nil || len(arts) != 1 {
		t.Fatalf("Walk = %+v, %v", arts, err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	r, err := OpenArtifact(arts[0])
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read/close = %v / %v", readErr, closeErr)
	}
	if string(body) != "inside" {
		t.Fatalf("opened %q, want pinned in-root target", body)
	}
}

func TestWalkSkipsSymlinkedArtifactOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.jsonl")
	mkfile(t, target, "{}")
	link := filepath.Join(root, "session.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 0 {
		t.Fatalf("got artifacts %+v, want none for out-of-root symlink target", arts)
	}
	if len(skips) != 1 || filepath.Base(skips[0].Path) != "session.jsonl" || !errors.Is(skips[0].Err, errSymlinkEscapesRoot) {
		t.Fatalf("got skips %+v, want one symlink escape skip", skips)
	}
}

// An unreadable subdirectory is skipped, not fatal: the rest of the tree is
// still discovered. (Permission bits are a no-op for root, so skip then.)
func TestWalkSkipsUnreadableSubtree(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission semantics differ for windows/root")
	}
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "good.jsonl"), "{}")
	locked := filepath.Join(root, "locked")
	mkfile(t, filepath.Join(locked, "hidden.jsonl"), "{}")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk should not fail on an unreadable subtree: %v", err)
	}
	if len(arts) != 1 || filepath.Base(arts[0].Path) != "good.jsonl" {
		t.Fatalf("got %+v, want only the readable artifact", arts)
	}
	// The unreadable subtree must be reported as a coverage gap, not hidden.
	if len(skips) != 1 || filepath.Base(skips[0].Path) != "locked" || skips[0].Err == nil {
		t.Fatalf("got skips %+v, want one skip for the locked subtree", skips)
	}
}

// A FIFO named like an artifact must be skipped, not opened: reading a pipe can
// block a scan forever. The walk records it as a coverage-gap Skip instead.
func TestWalkSkipsNonRegularFileInTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes differ on windows")
	}
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "good.jsonl"), "{}")
	fifo := filepath.Join(root, "pipe.jsonl")
	if err := makeFIFO(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || filepath.Base(arts[0].Path) != "good.jsonl" {
		t.Fatalf("got %+v, want only the regular artifact", arts)
	}
	if len(skips) != 1 || filepath.Base(skips[0].Path) != "pipe.jsonl" || skips[0].Err == nil {
		t.Fatalf("got skips %+v, want one skip for the FIFO", skips)
	}
}

// A symlink named like an artifact but pointing at a FIFO must be skipped before
// parsing. Symlinked regular files are allowed, but following a link to a FIFO
// in discover.Open would block the scan.
func TestWalkSkipsSymlinkToNonRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink and named pipe semantics differ on windows")
	}
	root := t.TempDir()
	fifo := filepath.Join(t.TempDir(), "pipe-target")
	if err := makeFIFO(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	link := filepath.Join(root, "session.jsonl")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 0 {
		t.Fatalf("got artifacts %+v, want none for a symlink to a FIFO", arts)
	}
	if len(skips) != 1 || filepath.Base(skips[0].Path) != "session.jsonl" || skips[0].Err == nil {
		t.Fatalf("got skips %+v, want one skip for the symlinked FIFO", skips)
	}
}

// A FIFO passed directly as the scan root is skipped the same way, so a
// single-file scan target cannot hang on a non-regular file.
func TestWalkSingleNonRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes differ on windows")
	}
	fifo := filepath.Join(t.TempDir(), "session.jsonl")
	if err := makeFIFO(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	arts, skips, err := Walk(fifo)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 0 {
		t.Fatalf("got %d artifacts, want 0 (FIFO is not a regular file)", len(arts))
	}
	if len(skips) != 1 || skips[0].Err == nil {
		t.Fatalf("got skips %+v, want one skip for the FIFO root", skips)
	}
}

func TestDefaultRoots(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	// No agent dirs yet: nothing returned.
	if roots := DefaultRoots(home); len(roots) != 0 {
		t.Fatalf("got %v, want no roots before any agent dir exists", roots)
	}
	claude := filepath.Join(home, ".claude", "projects")
	if err := os.MkdirAll(claude, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != claude {
		t.Fatalf("got %v, want [%q]", roots, claude)
	}

	// Once Gemini's tmp dir also exists, both roots are returned in the
	// fixed order DefaultRoots iterates (claude before gemini).
	gemini := filepath.Join(home, ".gemini", "tmp")
	if err := os.MkdirAll(gemini, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots = DefaultRoots(home)
	if len(roots) != 2 || roots[0] != claude || roots[1] != gemini {
		t.Fatalf("got %v, want [%q %q]", roots, claude, gemini)
	}
}

func TestDefaultRootsForAgents(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)

	claude := filepath.Join(home, ".claude", "projects")
	gemini := filepath.Join(home, ".gemini", "tmp")
	codexSessions := filepath.Join(home, ".codex", "sessions")
	codexArchive := filepath.Join(home, ".codex", "archived_sessions")
	for _, dir := range []string{claude, gemini, codexSessions, codexArchive} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", dir, err)
		}
	}
	codexHistory := filepath.Join(home, ".codex", "history.jsonl")
	mkfile(t, codexHistory, "{}\n")

	got := DefaultRootsFor(home, []string{model.AgentCodex, model.AgentCodex})
	want := []string{codexSessions, codexArchive, codexHistory}
	if !slices.Equal(got, want) {
		t.Fatalf("Codex roots = %v, want %v", got, want)
	}
	if got := DefaultRootsFor(home, []string{model.AgentClaudeCode, model.AgentGeminiCLI}); !slices.Equal(got, []string{claude, gemini}) {
		t.Fatalf("Claude/Gemini roots = %v, want [%q %q]", got, claude, gemini)
	}
	if got := DefaultRootsFor(home, []string{"not-an-agent"}); len(got) != 0 {
		t.Fatalf("unknown-agent roots = %v, want none", got)
	}
	if got, want := DefaultRootsFor(home, nil), DefaultRoots(home); !slices.Equal(got, want) {
		t.Fatalf("empty filter = %v, DefaultRoots = %v", got, want)
	}
}

func TestDefaultRootsHonorsRelocatedAgentStores(t *testing.T) {
	home := t.TempDir()
	claudeHome := filepath.Join(t.TempDir(), "claude-home")
	codexHome := filepath.Join(t.TempDir(), "codex-home")
	geminiHome := filepath.Join(t.TempDir(), "gemini-home")
	copilotHome := filepath.Join(t.TempDir(), "copilot-home")
	xdgDataHome := filepath.Join(t.TempDir(), "xdg-data")
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("GEMINI_CLI_HOME", geminiHome)
	t.Setenv("COPILOT_HOME", copilotHome)
	t.Setenv("XDG_DATA_HOME", xdgDataHome)

	claudeProjects := filepath.Join(claudeHome, "projects")
	codexSessions := filepath.Join(codexHome, "sessions")
	geminiTmp := filepath.Join(geminiHome, ".gemini", "tmp")
	copilotSessions := filepath.Join(copilotHome, "session-state")
	opencodeStorage := filepath.Join(xdgDataHome, "opencode", "storage")
	for _, dir := range []string{claudeProjects, codexSessions, geminiTmp, copilotSessions, opencodeStorage} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", dir, err)
		}
	}
	codexHistory := filepath.Join(codexHome, "history.jsonl")
	claudeHistory := filepath.Join(claudeHome, "history.jsonl")
	mkfile(t, codexHistory, "{}\n")
	mkfile(t, claudeHistory, "{}\n")

	roots := DefaultRoots(home)
	for _, want := range []string{claudeProjects, geminiTmp, codexSessions, copilotSessions, opencodeStorage, claudeHistory, codexHistory} {
		if !hasRoot(roots, want) {
			t.Fatalf("roots = %v, want relocated root %q", roots, want)
		}
	}
}

func TestDefaultRootsPreservesSpacesInOverridePath(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	codexHome := filepath.Join(t.TempDir(), "codex home with spaces")
	sessions := filepath.Join(codexHome, "sessions")
	if err := os.MkdirAll(sessions, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)
	if roots := DefaultRoots(home); !hasRoot(roots, sessions) {
		t.Fatalf("roots = %v, want untrimmed override %q", roots, sessions)
	}
}

func TestWalkClassifiesRelocatedCodexAndCopilotStores(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	codexHome := filepath.Join(t.TempDir(), "codex-data")
	copilotHome := filepath.Join(t.TempDir(), "copilot-data")
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("COPILOT_HOME", copilotHome)

	codexSession := filepath.Join(codexHome, "sessions", "2026", "07", "rollout.jsonl")
	codexHistory := filepath.Join(codexHome, "history.jsonl")
	copilotSession := filepath.Join(copilotHome, "session-state", "s1", "events.jsonl")
	for _, path := range []string{codexSession, codexHistory, copilotSession} {
		mkfile(t, path, "{}\n")
	}

	canonical := func(path string) string {
		t.Helper()
		resolved, err := absoluteResolvedPath(path)
		if err != nil {
			t.Fatalf("resolve %q: %v", path, err)
		}
		return resolved
	}
	want := map[string]string{
		canonical(codexSession):   model.AgentCodex,
		canonical(codexHistory):   model.AgentCodex,
		canonical(copilotSession): model.AgentCopilot,
	}
	got := map[string]string{}
	for _, root := range DefaultRoots(home) {
		arts, skips, err := Walk(root)
		if err != nil {
			t.Fatalf("Walk(%q): %v", root, err)
		}
		if len(skips) != 0 {
			t.Fatalf("Walk(%q) skips = %+v", root, skips)
		}
		for _, art := range arts {
			got[canonical(art.Path)] = art.Agent
		}
	}
	for path, agent := range want {
		if got[path] != agent {
			t.Errorf("artifact %q agent = %q, want %q (all: %v)", path, got[path], agent, got)
		}
	}
}

func TestDefaultRootsDedupesOverrideEqualToDefault(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	codexHome := filepath.Join(home, ".codex")
	t.Setenv("CODEX_HOME", codexHome)
	codexSessions := filepath.Join(codexHome, "sessions")
	if err := os.MkdirAll(codexSessions, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != codexSessions {
		t.Fatalf("roots = %v, want exactly one %q", roots, codexSessions)
	}
}

func TestDefaultRootsDedupesSymlinkedOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	home := t.TempDir()
	clearDefaultRootEnv(t)
	defaultHome := filepath.Join(home, ".codex")
	if err := os.MkdirAll(filepath.Join(defaultHome, "sessions"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkHome := filepath.Join(t.TempDir(), "codex-home")
	if err := os.Symlink(defaultHome, linkHome); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", linkHome)
	roots := DefaultRoots(home)
	if len(roots) != 1 {
		t.Fatalf("roots = %v, want one resolved store", roots)
	}
}

func hasRoot(roots []string, want string) bool {
	want = filepath.Clean(want)
	for _, got := range roots {
		if got == want {
			return true
		}
	}
	return false
}

func clearDefaultRootEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("COPILOT_HOME", "")
	t.Setenv("OPENCLAW_STATE_DIR", "")
	t.Setenv("OPENCLAW_HOME", "")
	t.Setenv("OPENCLAW_PROFILE", "")
	t.Setenv("PI_CODING_AGENT_SESSION_DIR", "")
	t.Setenv("PI_CODING_AGENT_DIR", "")
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
}

// Gemini keeps current and legacy session records under tmp/<project>/chats,
// plus older logs.json and checkpoint files directly below the project store.
// Other files in .gemini must not bleed into the Claude JSONL fallback.
func TestClassifyGeminiVsClaude(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"gemini logs json", filepath.Join(".gemini", "tmp", "abc123", "logs.json"), true, model.AgentGeminiCLI},
		{"gemini checkpoint json", filepath.Join(".gemini", "tmp", "abc123", "checkpoint-work.json"), true, model.AgentGeminiCLI},
		{"gemini checkpoint untagged", filepath.Join(".gemini", "tmp", "abc123", "checkpoint-.json"), true, model.AgentGeminiCLI},
		{"gemini current session", filepath.Join(".gemini", "tmp", "abc123", "chats", "session-1.jsonl"), true, model.AgentGeminiCLI},
		{"gemini subagent session", filepath.Join(".gemini", "tmp", "abc123", "chats", "parent", "child.jsonl"), true, model.AgentGeminiCLI},
		{"gemini legacy session", filepath.Join(".gemini", "tmp", "abc123", "chats", "s1.json"), true, model.AgentGeminiCLI},
		{"gemini arbitrary json outside chats", filepath.Join(".gemini", "tmp", "abc123", "state.json"), false, ""},
		// Non-transcript files under ~/.gemini must NOT be mis-tagged.
		{"gemini settings not transcript", filepath.Join(".gemini", "settings.json"), false, ""},
		{"gemini memory md not transcript", filepath.Join(".gemini", "GEMINI.md"), false, ""},
		{"gemini oauth not transcript", filepath.Join(".gemini", "oauth_creds.json"), false, ""},
		// A stray .jsonl under .gemini must not bleed into the Claude default.
		{"gemini stray jsonl not claude", filepath.Join(".gemini", "tmp", "abc123", "scratch.jsonl"), false, ""},
		// Claude workflow journals live under the projects tree but are internal
		// bookkeeping, not transcript rows.
		{"claude workflow journal not transcript", filepath.Join(".claude", "projects", "proj", "subagents", "workflows", "wf_1", "journal.jsonl"), false, ""},
		{"claude jsonl elsewhere", filepath.Join(".claude", "projects", "p", "s1.jsonl"), true, model.AgentClaudeCode},
		{"bare jsonl is claude", "session.jsonl", true, model.AgentClaudeCode},
		{"plain json outside gemini ignored", filepath.Join("some", "dir", "config.json"), false, ""},
		{"txt ignored", filepath.Join(".gemini", "tmp", "abc", "notes.txt"), false, ""},
		{"chat txt ignored", filepath.Join(".gemini", "tmp", "abc", "chats", "session.txt"), false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Anchor under a temp root so the path is realistic and absolute.
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

func TestClassifySkipsClaudeWorkflowJournalUnderConfiguredRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "claude-config")
	t.Setenv("CLAUDE_CONFIG_DIR", root)
	path := filepath.Join(root, "projects", "proj", "subagents", "workflows", "wf_1", "journal.jsonl")
	if artifact, ok := classify(path); ok {
		t.Fatalf("classify(%q) = %+v, want workflow journal skipped", path, artifact)
	}
}

// Claude Code stores internal subagent/workflow journals under the same
// ~/.claude/projects tree as transcripts. They must not be discovered as
// transcript artifacts, or normal scans emit noisy "unhandled entry type"
// diagnostics for expected workflow bookkeeping rows.
func TestWalkDropsClaudeInternalWorkflowJournals(t *testing.T) {
	root := t.TempDir()
	session := filepath.Join(root, ".claude", "projects", "proj", "session.jsonl")
	journal := filepath.Join(root, ".claude", "projects", "proj", "subagents", "workflows", "wf_1", "journal.jsonl")
	mkfile(t, session, "{}")
	mkfile(t, journal, `{"type":"started"}`)

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	if len(arts) != 1 {
		t.Fatalf("got %d artifacts, want only the real Claude session: %+v", len(arts), arts)
	}
	if filepath.Base(arts[0].Path) != "session.jsonl" || arts[0].Agent != model.AgentClaudeCode {
		t.Fatalf("got %+v, want the Claude session transcript", arts[0])
	}
}

// Antigravity shares the ~/.gemini root with Gemini CLI but keeps its files in
// DIFFERENT subdirs (config/ for hooks, antigravity/ for at-rest conversations).
// The gemini classifier must NOT mis-tag those as gemini-cli: a Gemini transcript
// is only a logs.json or checkpoint-<tag>.json under .gemini/tmp/, so files under
// .gemini/config/ or .gemini/antigravity/ never satisfy isGeminiArtifact. They are
// also not Antigravity artifacts in discovery — Antigravity is hook-only here (the
// .pb at-rest parser is out of scope), so the correct outcome is "not classified".
func TestGeminiNamespaceGuardExcludesAntigravity(t *testing.T) {
	cases := []struct {
		name string
		rel  string
	}{
		// The Antigravity hooks file auspex itself writes lives under .gemini/config/.
		{"antigravity hooks json not gemini", filepath.Join(".gemini", "config", "hooks.json")},
		// Antigravity at-rest conversations are protobuf under .gemini/antigravity/.
		{"antigravity pb not gemini", filepath.Join(".gemini", "antigravity", "conversations", "x.pb")},
		// A stray .jsonl under either Antigravity subdir must be dropped by the
		// underGeminiRoot guard, never bled into the Claude default.
		{"antigravity stray jsonl not claude", filepath.Join(".gemini", "antigravity", "conversations", "x.jsonl")},
		{"antigravity config stray jsonl not claude", filepath.Join(".gemini", "config", "scratch.jsonl")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok {
				t.Fatalf("classify(%q) = %q, want NOT classified (not gemini-cli, not claude-code)", path, art.Agent)
			}
		})
	}
}

// Walk over a mixed tree must tag each file by where it lives and what it is
// named: a logs.json under .gemini/tmp is Gemini while a sibling .jsonl under
// .claude/projects stays Claude. A non-transcript settings.json under .gemini is
// not picked up at all.
func TestWalkClassifiesGeminiAndClaudeInOneTree(t *testing.T) {
	root := t.TempDir()
	gem := filepath.Join(root, ".gemini", "tmp", "h1", "logs.json")
	settings := filepath.Join(root, ".gemini", "settings.json")
	cla := filepath.Join(root, ".claude", "projects", "p", "c.jsonl")
	mkfile(t, gem, "[]")
	mkfile(t, settings, "{}")
	mkfile(t, cla, "{}")

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	if len(arts) != 2 {
		t.Fatalf("got %d artifacts, want 2 (settings.json must be ignored): %+v", len(arts), arts)
	}
	got := map[string]string{}
	for _, a := range arts {
		got[filepath.Base(a.Path)] = a.Agent
	}
	if got["logs.json"] != model.AgentGeminiCLI {
		t.Errorf("logs.json agent = %q, want %q", got["logs.json"], model.AgentGeminiCLI)
	}
	if got["c.jsonl"] != model.AgentClaudeCode {
		t.Errorf("c.jsonl agent = %q, want %q", got["c.jsonl"], model.AgentClaudeCode)
	}
	if _, ok := got["settings.json"]; ok {
		t.Errorf("settings.json was classified as %q, want ignored", got["settings.json"])
	}
}

// A Codex rollout is classified by its .codex/sessions or .codex/archived_sessions
// directory marker, not just its extension: both plain .jsonl and the cold
// .jsonl.zst variant are Codex, and the marker keeps a Codex .jsonl from being
// mistaken for a Claude transcript. Codex classification runs before Gemini and
// Claude so the more specific path wins.
func TestClassifyCodex(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"codex jsonl", filepath.Join(".codex", "sessions", "2026", "06", "02", "rollout-x.jsonl"), true, model.AgentCodex},
		{"codex zst", filepath.Join(".codex", "sessions", "2026", "06", "02", "rollout-x.jsonl.zst"), true, model.AgentCodex},
		{"codex archived", filepath.Join(".codex", "archived_sessions", "rollout-y.jsonl"), true, model.AgentCodex},
		{"codex other file ignored", filepath.Join(".codex", "sessions", "history.txt"), false, ""},
		{"jsonl outside codex stays claude", filepath.Join(".claude", "projects", "p", "s.jsonl"), true, model.AgentClaudeCode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

func TestClassifyPi(t *testing.T) {
	clearDefaultRootEnv(t)
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"pi session", filepath.Join(".pi", "agent", "sessions", "--work-repo--", "2026-07-22_s.jsonl"), true, model.AgentPi},
		{"pi session case-insensitive extension", filepath.Join(".pi", "agent", "sessions", "--work-repo--", "s.JSONL"), true, model.AgentPi},
		{"pi non-jsonl ignored", filepath.Join(".pi", "agent", "sessions", "--work-repo--", "state.json"), false, ""},
		{"outside pi stays claude", filepath.Join(".claude", "projects", "p", "s.jsonl"), true, model.AgentClaudeCode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

func TestPiRelocatedSessionStore(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	store := filepath.Join(t.TempDir(), "pi sessions")
	t.Setenv("PI_CODING_AGENT_SESSION_DIR", store)
	file := filepath.Join(store, "--work-repo--", "s.jsonl")
	mkfile(t, file, "{}\n")

	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != store {
		t.Fatalf("roots = %v, want [%q]", roots, store)
	}
	arts, skips, err := Walk(store)
	if err != nil || len(skips) != 0 {
		t.Fatalf("Walk = artifacts %+v, skips %+v, error %v", arts, skips, err)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentPi {
		t.Fatalf("artifacts = %+v, want one Pi session", arts)
	}
}

func TestPiRelocatedAgentHome(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	agentHome := filepath.Join(t.TempDir(), "pi agent")
	t.Setenv("PI_CODING_AGENT_DIR", agentHome)
	store := filepath.Join(agentHome, "sessions")
	file := filepath.Join(store, "--work-repo--", "s.jsonl")
	mkfile(t, file, "{}\n")

	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != store {
		t.Fatalf("roots = %v, want [%q]", roots, store)
	}
	arts, skips, err := Walk(store)
	if err != nil || len(skips) != 0 || len(arts) != 1 || arts[0].Agent != model.AgentPi {
		t.Fatalf("Walk = artifacts %+v, skips %+v, error %v", arts, skips, err)
	}
}

func TestDefaultRootsIncludesPi(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	root := filepath.Join(home, piSessionsDir)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if roots := DefaultRoots(home); len(roots) != 1 || roots[0] != root {
		t.Fatalf("roots = %v, want [%q]", roots, root)
	}
}

func TestClassifyKimiCode(t *testing.T) {
	clearDefaultRootEnv(t)
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"main wire", filepath.Join(".kimi-code", "sessions", "wd_repo_abc", "session-1", "agents", "main", "wire.jsonl"), true, model.AgentKimiCode},
		{"sub-agent wire", filepath.Join(".kimi-code", "sessions", "wd_repo_abc", "session-1", "agents", "agent-0", "wire.JSONL"), true, model.AgentKimiCode},
		{"session index excluded", filepath.Join(".kimi-code", "session_index.jsonl"), false, ""},
		{"diagnostic log excluded", filepath.Join(".kimi-code", "sessions", "wd", "session", "logs", "debug.jsonl"), false, ""},
		{"wire outside agents excluded", filepath.Join(".kimi-code", "sessions", "wd", "session", "wire.jsonl"), false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

func TestKimiCodeRelocatedHome(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	kimiHome := filepath.Join(t.TempDir(), "kimi home")
	t.Setenv("KIMI_CODE_HOME", kimiHome)
	root := filepath.Join(kimiHome, "sessions")
	file := filepath.Join(root, "wd_repo_abc", "session-1", "agents", "main", "wire.jsonl")
	mkfile(t, file, "{}\n")

	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != root {
		t.Fatalf("roots = %v, want [%q]", roots, root)
	}
	arts, skips, err := Walk(root)
	if err != nil || len(skips) != 0 {
		t.Fatalf("Walk = artifacts %+v, skips %+v, error %v", arts, skips, err)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentKimiCode {
		t.Fatalf("artifacts = %+v, want one Kimi Code wire", arts)
	}
}

func TestDefaultRootsIncludesKimiCode(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	root := filepath.Join(home, kimiSessionsDir)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if roots := DefaultRoots(home); len(roots) != 1 || roots[0] != root {
		t.Fatalf("roots = %v, want [%q]", roots, root)
	}
}

// A Claude Cowork (local-agent-mode / Dispatch) audit.jsonl is classified by
// its "local-agent-mode-sessions" directory marker, not just its extension: the
// marker keeps a Cowork .jsonl from being mistaken for a Claude Code transcript,
// while a .jsonl outside that tree still defaults to Claude.
func TestClassifyCowork(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"cowork audit jsonl", filepath.Join("Library", "Application Support", "Claude", "local-agent-mode-sessions", "s1", "audit.jsonl"), true, model.AgentCowork},
		{"cowork audit JSONL case-insensitive", filepath.Join("Library", "Application Support", "Claude", "local-agent-mode-sessions", "s2", "audit.JSONL"), true, model.AgentCowork},
		{"cowork non-jsonl ignored", filepath.Join("Library", "Application Support", "Claude", "local-agent-mode-sessions", "s1", "meta.txt"), false, ""},
		{"jsonl outside cowork stays claude", filepath.Join(".claude", "projects", "p", "s.jsonl"), true, model.AgentClaudeCode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

// Walk over a Cowork transcript tree tags the audit.jsonl as AgentCowork.
func TestWalkClassifiesCowork(t *testing.T) {
	root := t.TempDir()
	audit := filepath.Join(root, "Library", "Application Support", "Claude", "local-agent-mode-sessions", "abc", "audit.jsonl")
	mkfile(t, audit, "{}")

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentCowork {
		t.Fatalf("got %+v, want one cowork artifact", arts)
	}
}

// A relative scan root (as the CLI's --path accepts) whose first segment is the
// Cowork marker must still classify as Cowork. The marker is then a leading
// prefix, not an infix, so without prefix matching the transcript would fall
// through to the bare-.jsonl Claude default and break the cowork identity. This
// is the regression guard for that path; the other cowork tests anchor under an
// absolute temp root and would not catch it.
func TestWalkClassifiesCoworkRelativeRoot(t *testing.T) {
	// classify is the unit under test: feed it the exact relative path a
	// --path scan of a relative root would walk.
	rel := filepath.Join(coworkPathMarker, "s1", "audit.jsonl")
	art, ok := classify(rel)
	if !ok || art.Agent != model.AgentCowork {
		t.Fatalf("classify(%q) = {%+v, %v}, want a cowork artifact", rel, art, ok)
	}

	// End-to-end: Walk a relative root from a chdir'd CWD so the paths it
	// classifies are themselves relative and marker-prefixed.
	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, coworkPathMarker, "s1", "audit.jsonl"), "{}")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	arts, _, err := Walk(coworkPathMarker)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentCowork {
		t.Fatalf("got %+v, want one cowork artifact from a relative root", arts)
	}
}

// A Cursor agent transcript is classified by its "agent-transcripts" directory
// marker, not just its extension: the marker keeps a Cursor .jsonl from being
// mistaken for a Claude Code transcript, while a .jsonl outside that tree still
// defaults to Claude. The sub-agent subdirectories/ subtree is matched too,
// since the marker can sit anywhere above the file.
func TestClassifyCursor(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"cursor transcript jsonl", filepath.Join(".cursor", "projects", "hash1", "agent-transcripts", "t1.jsonl"), true, model.AgentCursor},
		{"cursor transcript JSONL case-insensitive", filepath.Join(".cursor", "projects", "hash1", "agent-transcripts", "t2.JSONL"), true, model.AgentCursor},
		{"cursor sub-agent transcript", filepath.Join(".cursor", "projects", "hash1", "agent-transcripts", "subdirectories", "sub", "s1.jsonl"), true, model.AgentCursor},
		{"cursor non-jsonl ignored", filepath.Join(".cursor", "projects", "hash1", "agent-transcripts", "meta.txt"), false, ""},
		{"jsonl outside cursor stays claude", filepath.Join(".claude", "projects", "p", "s.jsonl"), true, model.AgentClaudeCode},
		// A .jsonl under .cursor/projects but OUTSIDE agent-transcripts/ is Cursor
		// bookkeeping, not a Claude transcript: it must NOT fall through to the
		// claude-code default (cross-agent bleed), so it stays unclassified.
		{"non-transcript jsonl under cursor root not claude", filepath.Join(".cursor", "projects", "hash1", "bookkeeping.jsonl"), false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

// A relative scan root (as the CLI's --path accepts) whose first segment is the
// Cursor marker must still classify as Cursor. The marker is then a leading
// prefix, not an infix, so without prefix matching the transcript would fall
// through to the bare-.jsonl Claude default and break the cursor identity. This
// is the regression guard for that path; the absolute cursor tests would not
// catch it.
func TestWalkClassifiesCursorRelativeRoot(t *testing.T) {
	// classify is the unit under test: feed it the exact relative path a --path
	// scan of a relative root would walk.
	rel := filepath.Join(cursorPathMarker, "t1.jsonl")
	art, ok := classify(rel)
	if !ok || art.Agent != model.AgentCursor {
		t.Fatalf("classify(%q) = {%+v, %v}, want a cursor artifact", rel, art, ok)
	}

	// End-to-end: Walk a relative root from a chdir'd CWD so the paths it
	// classifies are themselves relative and marker-prefixed.
	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, cursorPathMarker, "t1.jsonl"), "{}")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	arts, _, err := Walk(cursorPathMarker)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentCursor {
		t.Fatalf("got %+v, want one cursor artifact from a relative root", arts)
	}
}

// Walk over a Cursor project tree (absolute root) tags the transcript as
// AgentCursor, and a project tree that does not exist is simply absent rather
// than an error.
func TestWalkClassifiesCursorAbsoluteRoot(t *testing.T) {
	root := t.TempDir()
	transcript := filepath.Join(root, ".cursor", "projects", "abc", "agent-transcripts", "t1.jsonl")
	mkfile(t, transcript, "{}")

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentCursor {
		t.Fatalf("got %+v, want one cursor artifact", arts)
	}
}

// Walking a Cursor project root that holds BOTH a transcript and an unrelated
// .jsonl outside agent-transcripts/ classifies only the transcript as Cursor and
// drops the bookkeeping file entirely — it must never be mis-tagged claude-code,
// which the broader .cursor/projects scan root would otherwise allow.
func TestWalkCursorRootDropsNonTranscriptJSONL(t *testing.T) {
	root := t.TempDir()
	transcript := filepath.Join(root, ".cursor", "projects", "abc", "agent-transcripts", "t1.jsonl")
	bookkeeping := filepath.Join(root, ".cursor", "projects", "abc", "bookkeeping.jsonl")
	mkfile(t, transcript, "{}")
	mkfile(t, bookkeeping, "{}")

	arts, _, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 {
		t.Fatalf("got %d artifacts, want 1 (only the transcript): %+v", len(arts), arts)
	}
	// Compare by basename: on macOS t.TempDir() lives under /var/... which Walk
	// resolves to /private/var/..., so a full-path == would spuriously fail. The
	// single-artifact count above already proves the bookkeeping .jsonl was dropped;
	// the basename confirms the survivor is the transcript, not the bookkeeping file.
	if arts[0].Agent != model.AgentCursor || filepath.Base(arts[0].Path) != "t1.jsonl" {
		t.Fatalf("got %+v, want only the cursor transcript %q", arts[0], transcript)
	}
}

// DefaultRoots returns the Cursor projects dir once it exists, and omits it
// without erroring on a machine that never ran Cursor.
func TestDefaultRootsIncludesCursor(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	cursor := filepath.Join(home, ".cursor", "projects")
	if err := os.MkdirAll(cursor, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != cursor {
		t.Fatalf("got %v, want [%q]", roots, cursor)
	}
}

// DefaultRoots returns the Cowork sessions dir once it exists. Cowork joins the
// fixed iteration order after the Codex roots.
func TestDefaultRootsIncludesCowork(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	t.Setenv("APPDATA", "")
	t.Setenv("LOCALAPPDATA", "")
	candidates := CoworkRootCandidates(home)
	if len(candidates) == 0 {
		t.Skip("Cowork has no verified local endpoint store on this platform")
	}
	cowork := candidates[0]
	if err := os.MkdirAll(cowork, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != cowork {
		t.Fatalf("got %v, want [%q]", roots, cowork)
	}
}

func TestCoworkRootCandidatesByPlatform(t *testing.T) {
	home := filepath.Join("home", "user")
	mac := coworkRootCandidates("darwin", home)
	if len(mac) != 1 || !strings.Contains(filepath.ToSlash(mac[0]), "Library/Application Support/Claude/local-agent-mode-sessions") {
		t.Fatalf("macOS candidates = %v", mac)
	}
	for _, goos := range []string{"windows", "linux"} {
		if got := coworkRootCandidates(goos, home); len(got) != 0 {
			t.Fatalf("%s candidates = %v, want none without a verified store", goos, got)
		}
	}
}

func TestSlashIdentityPlatformCaseRules(t *testing.T) {
	path := `C:\Users\Alice\.CODEX\SESSIONS\rollout.JSONL`
	if got := slashIdentityForOS(path, "windows"); got != `c:/users/alice/.codex/sessions/rollout.jsonl` {
		t.Fatalf("Windows identity = %q", got)
	}
	if got := slashIdentityForOS(path, "linux"); got == strings.ToLower(got) {
		t.Fatalf("Unix identity unexpectedly folded case: %q", got)
	}
}

// Most machines have no Cowork transcript dir. DefaultRoots must simply omit it
// without erroring, so a scan on a machine that never ran Cowork reports nothing
// rather than failing.
func TestDefaultRootsToleratesAbsentCowork(t *testing.T) {
	home := t.TempDir() // empty: no agent dirs at all
	clearDefaultRootEnv(t)
	if roots := DefaultRoots(home); len(roots) != 0 {
		t.Fatalf("got %v, want no roots for an empty home", roots)
	}
}

// A Windsurf (Cascade) transcript is classified by its ".windsurf/transcripts"
// directory marker, not just its extension: the marker keeps a Windsurf .jsonl
// from being mistaken for a Claude Code transcript, while a .jsonl outside that
// tree still defaults to Claude. A .jsonl under .windsurf but OUTSIDE
// transcripts/ is Windsurf bookkeeping and must NOT bleed into the claude-code
// default.
func TestClassifyWindsurf(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"windsurf transcript jsonl", filepath.Join(".windsurf", "transcripts", "traj-1.jsonl"), true, model.AgentWindsurf},
		{"windsurf transcript JSONL case-insensitive", filepath.Join(".windsurf", "transcripts", "traj-2.JSONL"), true, model.AgentWindsurf},
		{"windsurf non-jsonl ignored", filepath.Join(".windsurf", "transcripts", "meta.txt"), false, ""},
		{"jsonl outside windsurf stays claude", filepath.Join(".claude", "projects", "p", "s.jsonl"), true, model.AgentClaudeCode},
		// A .jsonl under .windsurf but OUTSIDE transcripts/ is Windsurf bookkeeping,
		// not a Claude transcript: it must NOT fall through to the claude-code
		// default (cross-agent bleed), so it stays unclassified.
		{"non-transcript jsonl under windsurf root not claude", filepath.Join(".windsurf", "cache", "state.jsonl"), false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

// A relative scan root (as the CLI's --path accepts) whose first segment is the
// Windsurf marker must still classify as Windsurf. The marker is then a leading
// prefix, not an infix, so without prefix matching the transcript would fall
// through to the bare-.jsonl Claude default and break the windsurf identity. This
// is the regression guard for that path; the absolute windsurf tests would not
// catch it.
func TestWalkClassifiesWindsurfRelativeRoot(t *testing.T) {
	// classify is the unit under test: feed it the exact relative path a --path
	// scan of a relative root would walk.
	rel := filepath.Join(windsurfPathMarker, "traj-1.jsonl")
	art, ok := classify(rel)
	if !ok || art.Agent != model.AgentWindsurf {
		t.Fatalf("classify(%q) = {%+v, %v}, want a windsurf artifact", rel, art, ok)
	}

	// End-to-end: Walk a relative root from a chdir'd CWD so the paths it
	// classifies are themselves relative and marker-prefixed.
	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, windsurfPathMarker, "traj-1.jsonl"), "{}")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	arts, _, err := Walk(windsurfPathMarker)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentWindsurf {
		t.Fatalf("got %+v, want one windsurf artifact from a relative root", arts)
	}
}

// Walk over a Windsurf transcripts tree (absolute root) tags the transcript as
// AgentWindsurf, and a non-transcript .jsonl under .windsurf is dropped entirely —
// it must never be mis-tagged claude-code, which the broader .windsurf scan would
// otherwise allow.
func TestWalkClassifiesWindsurfAbsoluteRoot(t *testing.T) {
	root := t.TempDir()
	transcript := filepath.Join(root, ".windsurf", "transcripts", "traj-1.jsonl")
	bookkeeping := filepath.Join(root, ".windsurf", "cache", "state.jsonl")
	mkfile(t, transcript, "{}")
	mkfile(t, bookkeeping, "{}")

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	if len(arts) != 1 {
		t.Fatalf("got %d artifacts, want 1 (only the transcript): %+v", len(arts), arts)
	}
	// Compare by basename: on macOS t.TempDir() lives under /var/... which Walk
	// resolves to /private/var/..., so a full-path == would spuriously fail. The
	// single-artifact count above already proves the bookkeeping .jsonl was dropped;
	// the basename confirms the survivor is the transcript.
	if arts[0].Agent != model.AgentWindsurf || filepath.Base(arts[0].Path) != "traj-1.jsonl" {
		t.Fatalf("got %+v, want only the windsurf transcript %q", arts[0], transcript)
	}
}

// DefaultRoots returns the Windsurf transcripts dir once it exists, and omits it
// without erroring on a machine that never ran Windsurf (tolerate absent dir).
func TestDefaultRootsIncludesWindsurf(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	// Absent dir: not returned, no error.
	if roots := DefaultRoots(home); len(roots) != 0 {
		t.Fatalf("got %v, want no roots before any agent dir exists", roots)
	}
	windsurf := filepath.Join(home, ".windsurf", "transcripts")
	if err := os.MkdirAll(windsurf, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != windsurf {
		t.Fatalf("got %v, want [%q]", roots, windsurf)
	}
}

// A GitHub Copilot CLI at-rest event log is classified by BOTH its
// ".copilot/session-state" directory marker AND its exact events.jsonl basename:
// the marker keeps a Copilot .jsonl from being mistaken for a Claude Code
// transcript, while the basename keeps an UNRELATED .jsonl Copilot writes in the
// same tree (a plan, a checkpoint) from being mis-tagged a Copilot transcript. A
// .jsonl under .copilot but NOT a session-state events.jsonl is Copilot
// bookkeeping and must NOT bleed into the claude-code default.
func TestClassifyCopilot(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"copilot events jsonl", filepath.Join(".copilot", "session-state", "sess-1", "events.jsonl"), true, model.AgentCopilot},
		{"copilot events JSONL case-insensitive", filepath.Join(".copilot", "session-state", "sess-2", "EVENTS.JSONL"), true, model.AgentCopilot},
		// A non-events .jsonl in the same session-state tree must NOT be tagged
		// Copilot (exact basename required) and must NOT bleed into claude-code.
		{"non-events jsonl under session-state not claude", filepath.Join(".copilot", "session-state", "sess-1", "plan.jsonl"), false, ""},
		// A .jsonl under .copilot but OUTSIDE session-state is Copilot bookkeeping,
		// not a Claude transcript: it must NOT fall through to the claude-code
		// default (cross-agent bleed), so it stays unclassified.
		{"non-session-state jsonl under copilot root not claude", filepath.Join(".copilot", "cache", "state.jsonl"), false, ""},
		{"copilot non-jsonl ignored", filepath.Join(".copilot", "session-state", "sess-1", "events.txt"), false, ""},
		{"jsonl outside copilot stays claude", filepath.Join(".claude", "projects", "p", "s.jsonl"), true, model.AgentClaudeCode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

// A relative scan root (as the CLI's --path accepts) whose first segment is the
// Copilot marker must still classify as Copilot. The marker is then a leading
// prefix, not an infix, so without prefix matching the event log would fall
// through to the bare-.jsonl Claude default and break the copilot identity. This
// is the regression guard for that path; the absolute copilot tests would not
// catch it.
func TestWalkClassifiesCopilotRelativeRoot(t *testing.T) {
	rel := filepath.Join(copilotPathMarker, "sess-1", "events.jsonl")
	art, ok := classify(rel)
	if !ok || art.Agent != model.AgentCopilot {
		t.Fatalf("classify(%q) = {%+v, %v}, want a copilot artifact", rel, art, ok)
	}

	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, copilotPathMarker, "sess-1", "events.jsonl"), "{}")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	arts, _, err := Walk(copilotPathMarker)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentCopilot {
		t.Fatalf("got %+v, want one copilot artifact from a relative root", arts)
	}
}

// Walk over a Copilot session-state tree (absolute root) tags the events.jsonl as
// AgentCopilot, while a non-events .jsonl in the same tree and a non-session-state
// .jsonl under .copilot are both dropped entirely — neither may be mis-tagged
// claude-code, which the broader .copilot scan would otherwise allow.
func TestWalkClassifiesCopilotAbsoluteRoot(t *testing.T) {
	root := t.TempDir()
	events := filepath.Join(root, ".copilot", "session-state", "sess-1", "events.jsonl")
	plan := filepath.Join(root, ".copilot", "session-state", "sess-1", "plan.jsonl")
	bookkeeping := filepath.Join(root, ".copilot", "cache", "state.jsonl")
	mkfile(t, events, "{}")
	mkfile(t, plan, "{}")
	mkfile(t, bookkeeping, "{}")

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	if len(arts) != 1 {
		t.Fatalf("got %d artifacts, want 1 (only the events log): %+v", len(arts), arts)
	}
	// Compare by basename: on macOS t.TempDir() lives under /var/... which Walk
	// resolves to /private/var/..., so a full-path == would spuriously fail.
	if arts[0].Agent != model.AgentCopilot || filepath.Base(arts[0].Path) != "events.jsonl" {
		t.Fatalf("got %+v, want only the copilot events log %q", arts[0], events)
	}
}

// DefaultRoots returns the Copilot session-state dir once it exists, and omits it
// without erroring on a machine that never ran Copilot (tolerate absent dir).
func TestDefaultRootsIncludesCopilot(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	if roots := DefaultRoots(home); len(roots) != 0 {
		t.Fatalf("got %v, want no roots before any agent dir exists", roots)
	}
	copilot := filepath.Join(home, ".copilot", "session-state")
	if err := os.MkdirAll(copilot, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != copilot {
		t.Fatalf("got %v, want [%q]", roots, copilot)
	}
}

// DefaultRoots returns the Codex sessions dir once it exists, after the Claude
// and Gemini roots in the fixed iteration order.
func TestDefaultRootsIncludesCodex(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	codex := filepath.Join(home, ".codex", "sessions")
	if err := os.MkdirAll(codex, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != codex {
		t.Fatalf("got %v, want [%q]", roots, codex)
	}
}

// Open transparently decompresses a .jsonl.zst rollout so an extractor always
// reads plain JSONL, and passes a plain .jsonl through unchanged.
func TestOpenZstdRoundTrip(t *testing.T) {
	payload := `{"timestamp":"t","type":"session_meta","payload":{"id":"s"}}` + "\n"

	// Compressed path: write a real zstd .jsonl.zst and assert it decompresses.
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("new zstd writer: %v", err)
	}
	if _, err := enc.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close encoder: %v", err)
	}
	zpath := filepath.Join(t.TempDir(), "rollout.jsonl.zst")
	mkfile(t, zpath, buf.String())

	rc, err := Open(zpath)
	if err != nil {
		t.Fatalf("Open(zst): %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("read decompressed: %v", err)
	}
	if string(got) != payload {
		t.Errorf("decompressed = %q, want %q", got, payload)
	}

	// Plain path: a .jsonl is returned byte-for-byte.
	ppath := filepath.Join(t.TempDir(), "rollout.jsonl")
	mkfile(t, ppath, payload)
	rc2, err := Open(ppath)
	if err != nil {
		t.Fatalf("Open(jsonl): %v", err)
	}
	got2, err := io.ReadAll(rc2)
	rc2.Close()
	if err != nil {
		t.Fatalf("read plain: %v", err)
	}
	if string(got2) != payload {
		t.Errorf("plain read = %q, want %q", got2, payload)
	}
}

// A corrupt .jsonl.zst surfaces an error from Open rather than handing back a
// reader that fails mysteriously mid-stream.
func TestOpenZstdCorruptErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.jsonl.zst")
	mkfile(t, path, "not a zstd stream")
	rc, err := Open(path)
	if err != nil {
		// zstd validates the frame header lazily on first Read for some inputs;
		// either an Open error or a Read error is acceptable, both are surfaced.
		return
	}
	_, readErr := io.ReadAll(rc)
	rc.Close()
	if readErr == nil {
		t.Error("expected an error reading a corrupt zstd artifact, got nil")
	}
}

// TestClassifyOpenCode covers both earlier per-record JSON layouts while
// rejecting config files and non-JSON records.
func TestClassifyOpenCode(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"current part file", filepath.Join(".local", "share", "opencode", "storage", "part", "msg1", "prt1.json"), true, model.AgentOpenCode},
		{"current message file", filepath.Join(".local", "share", "opencode", "storage", "message", "s1", "m1.json"), true, model.AgentOpenCode},
		{"session metadata", filepath.Join(".local", "share", "opencode", "storage", "session", "proj1", "s1.json"), false, ""},
		{"session diff metadata", filepath.Join(".local", "share", "opencode", "storage", "session_diff", "s1.json"), false, ""},
		{"git-project slug layout", filepath.Join(".local", "share", "opencode", "project", "myproj", "storage", "part", "m", "p.json"), true, model.AgentOpenCode},
		{"global layout", filepath.Join(".local", "share", "opencode", "project", "global", "storage", "message", "s", "m.json"), true, model.AgentOpenCode},
		{"legacy session/part layout", filepath.Join(".local", "share", "opencode", "storage", "session", "part", "msg1", "item", "p.json"), true, model.AgentOpenCode},
		{"legacy project session/message layout", filepath.Join(".local", "share", "opencode", "project", "myproj", "storage", "session", "message", "s1", "m1.json"), true, model.AgentOpenCode},
		{"case-insensitive extension", filepath.Join(".local", "share", "opencode", "storage", "part", "m", "p.JSON"), true, model.AgentOpenCode},
		{"non-json under storage ignored", filepath.Join(".local", "share", "opencode", "storage", "part", "m", "p.txt"), false, ""},
		// A .json under opencode/ but OUTSIDE storage/ is config/auth/cache, not a
		// storage record: it must NOT be classified as an OpenCode artifact.
		{"json under opencode but outside storage", filepath.Join(".config", "opencode", "opencode.json"), false, ""},
		{"json outside opencode stays unclassified", filepath.Join("somewhere", "else", "data.json"), false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
		})
	}
}

// A relative scan root (as the CLI's --path accepts) whose first segment is the
// OpenCode storage marker must still classify as OpenCode. The marker is then a
// leading prefix, not an infix, so without prefix matching the record would be
// missed. This mirrors the Cursor/Cowork relative-root regression guards.
func TestWalkClassifiesOpenCodeRelativeRoot(t *testing.T) {
	rel := filepath.Join(opencodeStorageMarker, "part", "m", "p.json")
	art, ok := classify(rel)
	if !ok || art.Agent != model.AgentOpenCode {
		t.Fatalf("classify(%q) = {%+v, %v}, want an opencode artifact", rel, art, ok)
	}

	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, opencodeStorageMarker, "part", "m", "p.json"), "{}")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	arts, _, err := Walk(opencodeStorageMarker)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentOpenCode {
		t.Fatalf("got %+v, want one opencode artifact from a relative root", arts)
	}
}

// Walk over an OpenCode storage tree (absolute root) tags the part record as
// AgentOpenCode and drops a sibling non-record .json that lives outside storage/.
func TestWalkClassifiesOpenCodeAbsoluteRoot(t *testing.T) {
	root := t.TempDir()
	record := filepath.Join(root, ".local", "share", "opencode", "storage", "part", "m1", "p1.json")
	session := filepath.Join(root, ".local", "share", "opencode", "storage", "session", "project", "s1.json")
	diff := filepath.Join(root, ".local", "share", "opencode", "storage", "session_diff", "s1.json")
	config := filepath.Join(root, ".config", "opencode", "opencode.json")
	mkfile(t, record, "{}")
	mkfile(t, session, "{}")
	mkfile(t, diff, "[]")
	mkfile(t, config, "{}")

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	// Compare by basename: on macOS t.TempDir() resolves under /private/var/...,
	// so a full-path == would spuriously fail. The single-artifact count proves
	// the config .json was dropped; the basename confirms the survivor is the
	// storage record.
	if len(arts) != 1 || arts[0].Agent != model.AgentOpenCode || filepath.Base(arts[0].Path) != "p1.json" {
		t.Fatalf("got %+v, want only the opencode storage record", arts)
	}
}

// DefaultRoots returns the OpenCode storage dir once it exists, and omits it
// without erroring on a machine that never ran OpenCode.
func TestDefaultRootsIncludesOpenCode(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	storage := filepath.Join(home, ".local", "share", "opencode", "storage")
	if err := os.MkdirAll(storage, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != storage {
		t.Fatalf("got %v, want [%q]", roots, storage)
	}
}

func TestClassifyOpenClaw(t *testing.T) {
	t.Setenv("OPENCLAW_STATE_DIR", "")
	cases := []struct {
		name    string
		rel     string
		wantOK  bool
		wantAgt string
	}{
		{"session transcript", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.jsonl"), true, model.AgentOpenClaw},
		{"named profile transcript", filepath.Join(".openclaw-work", "agents", "a1", "sessions", "s1.jsonl"), true, model.AgentOpenClaw},
		{"invalid leading-dash profile root", filepath.Join(".openclaw--work", "agents", "a1", "sessions", "s1.jsonl"), true, model.AgentClaudeCode},
		{"default profile has no suffixed root", filepath.Join(".openclaw-default", "agents", "a1", "sessions", "s1.jsonl"), true, model.AgentClaudeCode},
		{"overlong profile root", filepath.Join(".openclaw-"+strings.Repeat("a", 65), "agents", "a1", "sessions", "s1.jsonl"), true, model.AgentClaudeCode},
		{"legacy state-root transcript", filepath.Join(".clawdbot", "agents", "a1", "sessions", "s1.jsonl"), true, model.AgentOpenClaw},
		{"topic thread variant", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1-topic-t9.jsonl"), true, model.AgentOpenClaw},
		{"case-insensitive extension", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.JSONL"), true, model.AgentOpenClaw},
		{"reset archive", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.jsonl.reset.2026-07-23T10-11-12.000Z"), true, model.AgentOpenClaw},
		{"deleted archive", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.jsonl.deleted.2026-07-23T10-11-12Z"), true, model.AgentOpenClaw},
		{"compressed archive unsupported in stable", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.jsonl.deleted.2026-07-23T10-11-12.000Z.zst"), false, ""},
		{"backup rotation ignored", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.jsonl.bak.2026-07-23T10-11-12.000Z"), false, ""},
		{"compaction checkpoint ignored", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.checkpoint.11111111-1111-4111-8111-111111111111.jsonl"), false, ""},
		{"trajectory sidecar ignored", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.trajectory.jsonl"), false, ""},
		{"migration rollback ignored", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.jsonl.migrated"), false, ""},
		{"malformed archive timestamp ignored", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.jsonl.deleted.yesterday"), false, ""},
		// Embedded-harness roots: agent/sessions and agent/codex-home/sessions are
		// also valid terminal layouts (the codex-home tree is a Codex-flavor store).
		{"agent embedded sessions", filepath.Join(".openclaw", "agents", "a1", "agent", "sessions", "s1.jsonl"), true, model.AgentOpenClaw},
		{"agent embedded cwd sessions", filepath.Join(".openclaw", "agents", "a1", "agent", "sessions", "--repo--", "s1.jsonl"), true, model.AgentOpenClaw},
		{"codex-home embedded sessions", filepath.Join(".openclaw", "agents", "a1", "agent", "codex-home", "sessions", "s1.jsonl"), true, model.AgentOpenClaw},
		{"codex-home dated sessions", filepath.Join(".openclaw", "agents", "a1", "agent", "codex-home", "sessions", "2026", "07", "23", "s1.jsonl"), true, model.AgentOpenClaw},
		{"codex-home arbitrary partition ignored", filepath.Join(".openclaw", "agents", "a1", "agent", "codex-home", "sessions", "foo", "bar", "baz", "s1.jsonl"), false, ""},
		{"codex-home short date ignored", filepath.Join(".openclaw", "agents", "a1", "agent", "codex-home", "sessions", "26", "7", "3", "s1.jsonl"), false, ""},
		{"codex-home invalid month ignored", filepath.Join(".openclaw", "agents", "a1", "agent", "codex-home", "sessions", "2026", "13", "03", "s1.jsonl"), false, ""},
		{"codex-home invalid day ignored", filepath.Join(".openclaw", "agents", "a1", "agent", "codex-home", "sessions", "2026", "02", "30", "s1.jsonl"), false, ""},
		{"codex-home without agent ignored", filepath.Join(".openclaw", "agents", "a1", "codex-home", "sessions", "s1.jsonl"), false, ""},
		// The session store index and the JSON5 config are NOT .jsonl transcripts.
		{"sessions store index ignored", filepath.Join(".openclaw", "agents", "a1", "sessions.json"), false, ""},
		{"openclaw config ignored", filepath.Join(".openclaw", "openclaw.json"), false, ""},
		// A .jsonl under .openclaw/agents but NOT under a sessions/ subtree is
		// bookkeeping, not a transcript: it must not be classified (and must not
		// bleed into the Claude default).
		{"jsonl under agents but outside sessions", filepath.Join(".openclaw", "agents", "a1", "notes.jsonl"), false, ""},
		{"jsonl under openclaw root outside agents", filepath.Join(".openclaw", "scratch.jsonl"), false, ""},
		{"non-jsonl under sessions ignored", filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.txt"), false, ""},
		// B2 regressions: a loose "/sessions/" substring must NOT match when
		// sessions/ is not the file's IMMEDIATE parent. cache/sessions/ and a nested
		// sessions/<subdir>/ both have a /sessions/ infix yet are not transcripts.
		{"cache sessions not a transcript", filepath.Join(".openclaw", "agents", "a1", "cache", "sessions", "s1.jsonl"), false, ""},
		{"nested under sessions not a transcript", filepath.Join(".openclaw", "agents", "a1", "sessions", "subdir", "s1.jsonl"), false, ""},
		{"too deep under embedded sessions", filepath.Join(".openclaw", "agents", "a1", "agent", "sessions", "cwd", "nested", "s1.jsonl"), false, ""},
		{"partial Codex date partition", filepath.Join(".openclaw", "agents", "a1", "agent", "codex-home", "sessions", "2026", "07", "s1.jsonl"), false, ""},
		// The agents segment must be anchored to the .openclaw root: a stray
		// agents/<id>/sessions/ tree elsewhere on disk must NOT be tagged OpenClaw
		// (a bare .jsonl outside any known root falls to the Claude default, so the
		// assertion is on the agent, not on ok).
		{"agents tree outside openclaw", filepath.Join("somewhere", "agents", "a1", "sessions", "s1.jsonl"), true, model.AgentClaudeCode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			art, ok := classify(path)
			if ok != c.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v", path, ok, c.wantOK)
			}
			if ok && art.Agent != c.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", path, art.Agent, c.wantAgt)
			}
			if art.Agent == model.AgentOpenClaw && c.wantAgt != model.AgentOpenClaw {
				t.Fatalf("classify(%q) wrongly tagged OpenClaw", path)
			}
		})
	}
}

func TestOpenClawTranscriptFileNames(t *testing.T) {
	archives := []struct {
		name string
		want bool
	}{
		{"s.jsonl.reset.2026-07-23T10-11-12Z", true},
		{"s.jsonl.deleted.2026-07-23T10-11-12.000Z", true},
		{"s.jsonl.deleted.2026-07-23T10-11-12.000Z.zst", false},
		{"s.jsonl.bak.2026-07-23T10-11-12.000Z", false},
		{"s.jsonl.deleted.yesterday", false},
		{"s.jsonl.deleted.2026-7-23T10-11-12Z", false},
		{"s.jsonl.deleted.2026-07-23T10-11-12.000Z.extra", false},
		{"s.deleted.2026-07-23T10-11-12.000Z", false},
		{"s.jsonl.zst", false},
	}
	for _, tc := range archives {
		if got := isOpenClawRetainedArchiveName(tc.name); got != tc.want {
			t.Errorf("isOpenClawRetainedArchiveName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}

	// Marker-looking ordinary names remain primary JSONL, matching OpenClaw's
	// isPrimarySessionTranscriptFileName contract; marker text alone is never
	// mistaken for a retained archive.
	if !isOpenClawTranscriptFileName("keep.deleted.keep.jsonl") {
		t.Errorf("marker-looking primary transcript was excluded")
	}
	if isOpenClawRetainedArchiveName("keep.deleted.keep.jsonl") {
		t.Errorf("marker-looking primary transcript was misclassified as an archive")
	}
}

// A relative scan root (as the CLI's --path accepts) whose first segment is the
// OpenClaw agents marker must still classify as OpenClaw. The marker is then a
// leading prefix, not an infix, so without prefix matching the transcript would
// be missed. This mirrors the Cursor/Cowork/OpenCode relative-root guards.
func TestWalkClassifiesOpenClawRelativeRoot(t *testing.T) {
	rel := filepath.Join(".openclaw", "agents", "a1", "sessions", "s1.jsonl")
	art, ok := classify(rel)
	if !ok || art.Agent != model.AgentOpenClaw {
		t.Fatalf("classify(%q) = {%+v, %v}, want an openclaw artifact", rel, art, ok)
	}

	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, rel), "{}")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	arts, _, err := Walk(".openclaw")
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentOpenClaw {
		t.Fatalf("got %+v, want one openclaw artifact from a relative root", arts)
	}
}

// Walk over an OpenClaw tree (absolute root) tags the session transcript as
// AgentOpenClaw and drops the sessions.json store index that shares the
// directory.
func TestWalkClassifiesOpenClawAbsoluteRoot(t *testing.T) {
	root := t.TempDir()
	transcript := filepath.Join(root, ".openclaw", "agents", "a1", "sessions", "s1.jsonl")
	index := filepath.Join(root, ".openclaw", "agents", "a1", "sessions.json")
	mkfile(t, transcript, "{}")
	mkfile(t, index, "{}")

	arts, skips, err := Walk(root)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("got %d skips, want 0: %+v", len(skips), skips)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentOpenClaw || filepath.Base(arts[0].Path) != "s1.jsonl" {
		t.Fatalf("got %+v, want only the openclaw transcript", arts)
	}
}

// DefaultRoots returns the OpenClaw agents dir once it exists, and omits it
// without erroring on a machine that never ran OpenClaw.
func TestDefaultRootsIncludesOpenClaw(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	agents := filepath.Join(home, ".openclaw", "agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != agents {
		t.Fatalf("got %v, want [%q]", roots, agents)
	}
}

func TestDefaultRootsHonorsOpenClawStateDir(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	staleDefault := filepath.Join(home, ".openclaw", "agents")
	if err := os.MkdirAll(staleDefault, 0o755); err != nil {
		t.Fatalf("mkdir stale default: %v", err)
	}
	stateDir := filepath.Join(t.TempDir(), "openclaw state")
	agents := filepath.Join(stateDir, "agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)

	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != agents {
		t.Fatalf("got %v, want only authoritative relocated OpenClaw root [%q]", roots, agents)
	}
}

func TestDefaultRootsHonorsOpenClawHome(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	openClawHome := filepath.Join(t.TempDir(), "service-home")
	agents := filepath.Join(openClawHome, ".openclaw", "agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("OPENCLAW_HOME", openClawHome)

	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != agents {
		t.Fatalf("got %v, want OPENCLAW_HOME root [%q]", roots, agents)
	}
}

func TestDefaultRootsIgnoresOpenClawProfileWithoutStateDir(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	profileAgents := filepath.Join(home, ".openclaw-work", "agents")
	if err := os.MkdirAll(profileAgents, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	legacyAgents := filepath.Join(home, ".clawdbot", "agents")
	if err := os.MkdirAll(legacyAgents, 0o755); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}
	t.Setenv("OPENCLAW_PROFILE", "work")

	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != legacyAgents {
		t.Fatalf("got %v, want legacy root [%q]; OPENCLAW_PROFILE alone is not a path selector", roots, legacyAgents)
	}

	stateAgents := filepath.Join(t.TempDir(), "explicit-state", "agents")
	if err := os.MkdirAll(stateAgents, 0o755); err != nil {
		t.Fatalf("mkdir explicit state: %v", err)
	}
	t.Setenv("OPENCLAW_STATE_DIR", filepath.Dir(stateAgents))
	roots = DefaultRoots(home)
	if len(roots) != 1 || roots[0] != stateAgents {
		t.Fatalf("got %v, want explicit state root [%q]", roots, stateAgents)
	}
}

func TestDefaultRootsHonorsOpenClawLegacyFallback(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	legacyAgents := filepath.Join(home, ".clawdbot", "agents")
	if err := os.MkdirAll(legacyAgents, 0o755); err != nil {
		t.Fatalf("mkdir legacy root: %v", err)
	}

	roots := DefaultRoots(home)
	if len(roots) != 1 || roots[0] != legacyAgents {
		t.Fatalf("got %v, want legacy OpenClaw root [%q]", roots, legacyAgents)
	}

	currentAgents := filepath.Join(home, ".openclaw", "agents")
	if err := os.MkdirAll(currentAgents, 0o755); err != nil {
		t.Fatalf("mkdir current root: %v", err)
	}
	roots = DefaultRoots(home)
	if len(roots) != 1 || roots[0] != currentAgents {
		t.Fatalf("got %v, want current OpenClaw root [%q] to win", roots, currentAgents)
	}
}

func TestClassifyOpenClawStateDir(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "relocated-openclaw")
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)

	cases := []struct {
		name    string
		path    string
		wantOK  bool
		wantAgt string
	}{
		{
			name:    "session transcript",
			path:    filepath.Join(stateDir, "agents", "a1", "sessions", "s1.jsonl"),
			wantOK:  true,
			wantAgt: model.AgentOpenClaw,
		},
		{
			name:    "embedded codex home transcript",
			path:    filepath.Join(stateDir, "agents", "a1", "agent", "codex-home", "sessions", "s1.jsonl"),
			wantOK:  true,
			wantAgt: model.AgentOpenClaw,
		},
		{
			name:   "nested lookalike agents tree",
			path:   filepath.Join(stateDir, "cache", "agents", "a1", "sessions", "s1.jsonl"),
			wantOK: false,
		},
		{
			name:   "nested below sessions",
			path:   filepath.Join(stateDir, "agents", "a1", "sessions", "nested", "s1.jsonl"),
			wantOK: false,
		},
		{
			name:   "bookkeeping jsonl does not bleed into Claude",
			path:   filepath.Join(stateDir, "agents", "a1", "diagnostics.jsonl"),
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			art, ok := classify(tc.path)
			if ok != tc.wantOK {
				t.Fatalf("classify(%q) ok = %v, want %v (artifact: %+v)", tc.path, ok, tc.wantOK, art)
			}
			if ok && art.Agent != tc.wantAgt {
				t.Fatalf("classify(%q) agent = %q, want %q", tc.path, art.Agent, tc.wantAgt)
			}
		})
	}
}

func TestWalkRelocatedOpenClawStateDir(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	stateDir := filepath.Join(t.TempDir(), "openclaw-state")
	t.Setenv("OPENCLAW_STATE_DIR", stateDir)
	transcript := filepath.Join(stateDir, "agents", "a1", "sessions", "s1.jsonl")
	bookkeeping := filepath.Join(stateDir, "agents", "a1", "diagnostics.jsonl")
	mkfile(t, transcript, "{}\n")
	mkfile(t, bookkeeping, "{}\n")

	roots := DefaultRoots(home)
	if len(roots) != 1 {
		t.Fatalf("DefaultRoots() = %v, want one relocated OpenClaw root", roots)
	}
	arts, skips, err := Walk(roots[0])
	if err != nil {
		t.Fatalf("Walk(%q): %v", roots[0], err)
	}
	if len(skips) != 0 {
		t.Fatalf("Walk(%q) skips = %+v, want none", roots[0], skips)
	}
	if len(arts) != 1 || arts[0].Agent != model.AgentOpenClaw || !samePath(arts[0].Path, transcript) {
		t.Fatalf("Walk(%q) = %+v, want only OpenClaw transcript %q", roots[0], arts, transcript)
	}
}

func mkfile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
