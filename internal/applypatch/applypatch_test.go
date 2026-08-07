package applypatch

import "testing"

func TestParse(t *testing.T) {
	patch := "*** Begin Patch\n" +
		"*** Add File: new.go\n+package p\n" +
		"*** Update File: old.go\n@@\n+*** Delete File: bait.go\n" +
		"*** Move to: moved.go\n" +
		"*** Delete File: gone.go\n*** End Patch\n"
	got := Parse(patch)
	want := []Change{
		{Path: "new.go"},
		{Path: "old.go", Delete: true},
		{Path: "moved.go"},
		{Path: "gone.go", Delete: true},
	}
	if len(got) != len(want) {
		t.Fatalf("Parse() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Parse()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseBareEnvelope(t *testing.T) {
	got := Parse("*** Update File: a.go\n@@\n-old\n+new\n")
	if len(got) != 1 || got[0] != (Change{Path: "a.go"}) {
		t.Fatalf("Parse() = %+v", got)
	}
}

func TestDigest(t *testing.T) {
	sha, n := Digest("patch")
	if sha != "a4895eb44afc336fecbba6e520cd67e178dace0276655d102fceffa8e5f70570" || n != 5 {
		t.Fatalf("Digest() = %q, %d", sha, n)
	}
	if sha, n := Digest(""); sha != "" || n != 0 {
		t.Fatalf("Digest(empty) = %q, %d", sha, n)
	}
}
