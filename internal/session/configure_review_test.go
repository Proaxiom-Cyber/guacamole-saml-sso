package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

func draftFixture(t *testing.T) (*Options, *state.State) {
	t.Helper()
	t.Setenv("GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN", "fixture-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/zones" {
			t.Errorf("configuration made unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 400)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":[{"id":"zone","name":"website.test","status":"active","account":{"id":"account","name":"Test account"}}]}`)
	}))
	t.Cleanup(server.Close)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o := &Options{StateDir: t.TempDir(), InstallDir: filepath.Join(root, "install"), Cloudflare: &cloudflare.Client{Base: server.URL, HTTP: server.Client(), Token: func(context.Context) (string, error) { return "fixture-token", nil }}, MountedStorage: func(context.Context) ([]mountedStorage, error) {
		return []mountedStorage{{Target: "/", Source: "/dev/root", FSType: "xfs"}}, nil
	}, DiscoverTenant: func(_ context.Context, domain string) (string, error) {
		if domain != "identity.test" {
			t.Errorf("wrong tenant domain %s", domain)
		}
		return "11111111-2222-3333-4444-555555555555", nil
	}}
	return o, &state.State{DeploymentID: "draft", Config: map[string]string{"credential-mode": "env"}}
}

// Domain, hostname, tenant, groups, mounted root, recording budget, no backups.
const draftAnswers = "1\nfirst\nidentity.test\n\n\n1\n20GiB\n3\n"

func TestDraftBackEditsBeforeApproval(t *testing.T) {
	o, st := draftFixture(t)
	// Edit hostname from review, then accept the other saved answers again.
	u, _ := testUI(true, draftAnswers+"2\nsecond\n\n\n\n1\n\n3\np\n")
	if err := o.configureReview(context.Background(), st, u); err != nil {
		t.Fatal(err)
	}
	if st.Config["guac-hostname"] != "second.website.test" || st.Config["setup-plan-approved"] != "true" {
		t.Fatalf("wrong approved plan: %v", st.Config)
	}
	if len(st.Resources) != 0 {
		t.Fatal("configuration created resources")
	}
	if st.Config["entra-discovered-tenant-id"] == "" {
		t.Fatal("tenant ID was not discovered")
	}
	if o.EntraTenant == "identity.test" {
		t.Fatal("sign-in did not receive the discovered ID")
	}
}
func TestDraftSaveDoesNotApproveOrDeploy(t *testing.T) {
	o, st := draftFixture(t)
	u, _ := testUI(true, draftAnswers+"q\n")
	if err := o.configureReview(context.Background(), st, u); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if st.Config["setup-plan-approved"] != "" || st.Config["guac-hostname"] != "" || len(st.Resources) > 0 {
		t.Fatal("saved draft was deployed")
	}
	var d map[string]string
	if err := json.Unmarshal([]byte(st.Config["setup-draft"]), &d); err != nil {
		t.Fatal(err)
	}
	if d["guac-hostname"] != "first.website.test" {
		t.Fatal("draft answers were lost")
	}
}
func TestRecordingMountDisconnectBlocksApply(t *testing.T) {
	o, st := draftFixture(t)
	st.Config = map[string]string{"recording-mount-target": "/mnt/share", "recording-mount-source": "server:/recordings", "recording-mount-type": "nfs4"}
	if err := o.validateRecordingMount(context.Background(), st); err == nil {
		t.Fatal("missing mount accepted")
	}
}
func TestMountPickerExcludesReadOnlyAndVirtualStorage(t *testing.T) {
	mounts, err := parseMountedStorage([]byte(`{"filesystems":[{"target":"/","source":"/dev/root","fstype":"xfs","options":"rw","children":[{"target":"/proc","fstype":"proc","options":"rw"},{"target":"/mnt/archive","fstype":"ext4","options":"ro"},{"target":"/mnt/share","source":"host:/share","fstype":"nfs4","options":"rw"}]}]}`))
	if err != nil || len(mounts) != 2 || mounts[1].Target != "/mnt/share" {
		t.Fatalf("wrong mount list: %+v %v", mounts, err)
	}
}
func TestTenantIssuerMustIdentifySpecificMicrosoftTenant(t *testing.T) {
	id := "11111111-2222-3333-4444-555555555555"
	if got, err := tenantIDFromIssuer("https://login.microsoftonline.com/" + id + "/v2.0"); err != nil || got != id {
		t.Fatal(got, err)
	}
	for _, issuer := range []string{"https://example.com/" + id + "/v2.0", "https://login.microsoftonline.com/organizations/v2.0", "http://login.microsoftonline.com/" + id + "/v2.0"} {
		if _, err := tenantIDFromIssuer(issuer); err == nil {
			t.Fatal("accepted " + issuer)
		}
	}
}
func TestUnapprovedDraftRunsBeforeHostInstallation(t *testing.T) {
	phases := Phases(&Options{})
	names := []string{}
	for _, p := range phases {
		names = append(names, p.Name)
	}
	s := strings.Join(names, ",")
	if strings.Index(s, "configure-review") > strings.Index(s, "host-dependencies") {
		t.Fatal("dependencies installed before approval")
	}
}

func TestEncryptedBackupPassphraseNeverEntersDraft(t *testing.T) {
	o, st := draftFixture(t)
	answers := strings.TrimSuffix(draftAnswers, "3\n") + "1\n\n\n\nq\n"
	u, _ := testUI(true, answers)
	u.Secret = func(string) (string, error) { return "fixture-recovery-passphrase", nil }
	if err := o.configureReview(context.Background(), st, u); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	serialized, _ := json.Marshal(st)
	if strings.Contains(string(serialized), "fixture-recovery-passphrase") {
		t.Fatal("passphrase persisted in draft")
	}
	if len(st.Resources) != 0 {
		t.Fatal("backup key created before approval")
	}
}

func TestSetupPickerExplainsSelectedStorageAndNavigation(t *testing.T) {
	u, out := testUI(true, "1\n")
	i, err := chooseSetupItem(u, "Choose storage", []string{"/mnt/recordings"}, "Use the connected recording filesystem.")
	if err != nil || i != 0 {
		t.Fatalf("selection: %d %v", i, err)
	}
	if !strings.Contains(out.String(), "Use the connected recording filesystem.") || !strings.Contains(out.String(), "Going back does not undo resources") {
		t.Fatal("storage or navigation explanation missing")
	}
}
