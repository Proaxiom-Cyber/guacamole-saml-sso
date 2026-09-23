package session

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func TestRecordingLocationPreservesChoiceAndRejectsExistingDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "new-recordings")
	o := Options{InstallDir: filepath.Join(root, "install"), RecordingDir: path}
	st := &state.State{Config: map[string]string{}}
	u := &ui.UI{In: bufio.NewReader(strings.NewReader("")), Out: &bytes.Buffer{}}
	if err := o.selectRecordingLocation(st, u); err != nil {
		t.Fatal(err)
	}
	if st.Config["recording-dir"] != path {
		t.Fatal("choice not saved")
	}
	o.RecordingDir = ""
	if err := o.selectRecordingLocation(st, u); err != nil {
		t.Fatal(err)
	}
	o.RecordingDir = filepath.Join(root, "different")
	if err := o.selectRecordingLocation(st, u); err == nil {
		t.Fatal("silent migration allowed")
	}
	st.Config = map[string]string{}
	o.RecordingDir = root
	if err := o.selectRecordingLocation(st, u); err == nil {
		t.Fatal("existing directory accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	o.RecordingDir = filepath.Join(link, "child")
	if err := o.selectRecordingLocation(st, u); err == nil {
		t.Fatal("symlink parent accepted")
	}
}
