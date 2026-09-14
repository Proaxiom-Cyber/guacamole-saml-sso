package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/host"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

func kernelHost(t *testing.T, pending, booted *bool, installs *int) *host.Probes {
	t.Helper()
	p := fakeHost(t)
	p.Run = func(_ context.Context, name string, args ...string) (string, error) {
		switch name {
		case "modprobe":
			if *booted || len(args) > 0 && args[0] == "-S" && *pending {
				return "", nil
			}
			return "module unavailable", errors.New("exit 1")
		case "grubby":
			return "/boot/vmlinuz-6.12-test.x86_64\n", nil
		case "dnf":
			if strings.Join(args, " ") != "-y install kernel kernel-modules kernel-modules-extra" {
				t.Fatalf("unexpected kernel repair: %v", args)
			}
			*installs++
			*pending = true
		}
		return "ok", nil
	}
	return p
}

func TestKernelRepairRequiresConsentAndResumesAfterReboot(t *testing.T) {
	pending, booted, installs := false, false, 0
	h := kernelHost(t, &pending, &booted, &installs)
	dir := t.TempDir()
	u, _ := testUI(false, "")
	o := Options{StateDir: dir, UI: u, Host: h, CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}}
	err := Run(context.Background(), core(o))
	if !errors.Is(err, ErrApprovalRequired) || installs != 0 {
		t.Fatalf("repair without approval: installs=%d err=%v", installs, err)
	}
	o.Resume, o.InstallDependencies = true, true
	err = Run(context.Background(), core(o))
	if !errors.Is(err, host.ErrRebootRequired) || installs != 1 {
		t.Fatalf("approved repair: installs=%d err=%v", installs, err)
	}
	st, err := state.Read(dir)
	if err != nil || st.Config["host-kernel-packages"] == "" {
		t.Fatalf("kernel repair was not recorded: state=%+v err=%v", st, err)
	}
	// Retrying before reboot must not reinstall packages or start later phases.
	err = Run(context.Background(), core(o))
	if !errors.Is(err, host.ErrRebootRequired) || installs != 1 {
		t.Fatalf("retry before reboot: installs=%d err=%v", installs, err)
	}
	booted = true
	if err := Run(context.Background(), core(o)); err != nil || installs != 1 {
		t.Fatalf("resume after reboot: installs=%d err=%v", installs, err)
	}
}

func TestKernelRepairCanBeDeclined(t *testing.T) {
	pending, booted, installs := false, false, 0
	u, _ := testUI(true, "y\nn\n")
	err := Run(context.Background(), core(Options{
		StateDir: t.TempDir(), UI: u, Host: kernelHost(t, &pending, &booted, &installs),
	}))
	if err == nil || !strings.Contains(err.Error(), "declined") || installs != 0 {
		t.Fatalf("declined repair: installs=%d err=%v", installs, err)
	}
}

func TestPendingKernelOnlyRequiresReboot(t *testing.T) {
	pending, booted, installs := true, false, 0
	u, _ := testUI(false, "")
	err := Run(context.Background(), core(Options{
		StateDir: t.TempDir(), UI: u, Host: kernelHost(t, &pending, &booted, &installs),
	}))
	if !errors.Is(err, host.ErrRebootRequired) || installs != 0 {
		t.Fatalf("pending kernel: installs=%d err=%v", installs, err)
	}
}

func TestKernelRepairDoesNotRunOnUnsupportedHost(t *testing.T) {
	pending, booted, installs := false, false, 0
	h := kernelHost(t, &pending, &booted, &installs)
	h.Geteuid = func() int { return 1000 }
	u, _ := testUI(false, "")
	err := Run(context.Background(), core(Options{
		StateDir: t.TempDir(), UI: u, Host: h, InstallDependencies: true,
	}))
	if err == nil || !strings.Contains(err.Error(), "root privileges") || installs != 0 {
		t.Fatalf("unsupported host: installs=%d err=%v", installs, err)
	}
}

func TestKernelRepairDoesNotTrustSuccessfulPackageExit(t *testing.T) {
	pending, booted, installs := false, false, 0
	h := kernelHost(t, &pending, &booted, &installs)
	run := h.Run
	h.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := run(ctx, name, args...)
		if name == "dnf" {
			pending = false
		}
		return out, err
	}
	u, _ := testUI(false, "")
	err := Run(context.Background(), core(Options{
		StateDir: t.TempDir(), UI: u, Host: h, InstallDependencies: true,
	}))
	if err == nil || !strings.Contains(err.Error(), "unavailable for both") || installs != 1 {
		t.Fatalf("unverified repair continued: installs=%d err=%v", installs, err)
	}
}
