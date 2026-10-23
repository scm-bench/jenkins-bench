package checks

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// metaJSON renders metadata the way a control directory stores it.
func metaJSON(t *testing.T, m Metadata) *fstest.MapFile {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return &fstest.MapFile{Data: raw}
}

func supplement(id string) Metadata {
	m := valid()
	m.ID = id
	m.CISID = ""
	return m
}

// failingFS lists every file of the wrapped FS but refuses to open the named
// ones, the way an unreadable file shows up in a directory listing.
type failingFS struct {
	fstest.MapFS
	fail map[string]bool
}

func (f failingFS) Open(name string) (fs.File, error) {
	if f.fail[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return f.MapFS.Open(name)
}

func (f failingFS) ReadFile(name string) ([]byte, error) {
	if f.fail[name] {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrPermission}
	}
	return f.MapFS.ReadFile(name)
}

func TestLoadFromOrdersSupplementsAfterTheMappingByID(t *testing.T) {
	numbered := valid()
	fsys := fstest.MapFS{
		"policies/jenkins/z/metadata.json":   metaJSON(t, supplement("SUP-B")),
		"policies/jenkins/y/metadata.json":   metaJSON(t, supplement("SUP-A")),
		"policies/jenkins/x/metadata.json":   metaJSON(t, numbered),
		"policies/jenkins/x/check.rego":      {Data: []byte("package x")},
		"policies/jenkins/x/check_test.rego": {Data: []byte("package x_test")},
		"policies/jenkins/x/README.json":     {Data: []byte("not metadata")},
		"policies/jenkins/x/notes.txt":       {Data: []byte("ignored")},
	}
	b, err := loadFrom(fsys)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range b.Checks {
		ids = append(ids, c.ID)
	}
	if got, want := strings.Join(ids, ","), numbered.ID+",SUP-A,SUP-B"; got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
	if len(b.Modules) != 1 || b.Modules[0].Path != "policies/jenkins/x/check.rego" {
		t.Errorf("modules = %+v, want only the non-test check.rego", b.Modules)
	}
}

func TestLoadFromRejectsABrokenBundle(t *testing.T) {
	good := valid()
	invalid := valid()
	invalid.Title = ""
	cases := []struct {
		name string
		fsys fs.FS
		want string
	}{
		{
			name: "no policies directory",
			fsys: fstest.MapFS{},
			want: "policies",
		},
		{
			name: "unknown field",
			fsys: fstest.MapFS{
				"policies/jenkins/a/metadata.json": {Data: []byte(`{"id":"X","surprise":1}`)},
			},
			want: "parse policies/jenkins/a/metadata.json",
		},
		{
			name: "invalid control",
			fsys: fstest.MapFS{
				"policies/jenkins/a/metadata.json": metaJSON(t, invalid),
			},
			want: "title is required",
		},
		{
			name: "duplicate id",
			fsys: fstest.MapFS{
				"policies/jenkins/a/metadata.json": metaJSON(t, good),
				"policies/jenkins/b/metadata.json": metaJSON(t, good),
			},
			want: "duplicate check ID " + good.ID,
		},
		{
			name: "unreadable module",
			fsys: failingFS{
				MapFS: fstest.MapFS{"policies/jenkins/a/check.rego": {Data: []byte("package a")}},
				fail:  map[string]bool{"policies/jenkins/a/check.rego": true},
			},
			want: "read policies/jenkins/a/check.rego",
		},
		{
			name: "unreadable metadata",
			fsys: failingFS{
				MapFS: fstest.MapFS{"policies/jenkins/a/metadata.json": metaJSON(t, good)},
				fail:  map[string]bool{"policies/jenkins/a/metadata.json": true},
			},
			want: "read policies/jenkins/a/metadata.json",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := loadFrom(tc.fsys)
			if err == nil {
				t.Fatalf("loaded %d checks, want an error", len(b.Checks))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadFromSurfacesPermissionErrors(t *testing.T) {
	fsys := failingFS{
		MapFS: fstest.MapFS{"policies/jenkins/a/check.rego": {Data: []byte("package a")}},
		fail:  map[string]bool{"policies/jenkins/a/check.rego": true},
	}
	if _, err := loadFrom(fsys); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("error = %v, want it to wrap fs.ErrPermission", err)
	}
}

func TestLessCheckPutsSupplementsLast(t *testing.T) {
	mapped := Check{Metadata: valid()}
	supA := Check{Metadata: supplement("SUP-A")}
	supB := Check{Metadata: supplement("SUP-B")}
	cases := []struct {
		a, b Check
		want bool
	}{
		{mapped, supA, true},
		{supA, mapped, false},
		{supA, supB, true},
		{supB, supA, false},
		{mapped, mapped, false},
	}
	for _, tc := range cases {
		if got := lessCheck(tc.a, tc.b); got != tc.want {
			t.Errorf("lessCheck(%s, %s) = %v, want %v", tc.a.ID, tc.b.ID, got, tc.want)
		}
	}
}
