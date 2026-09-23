package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func (o *Options) selectRecordingLocation(st *state.State, u *ui.UI) error {
	saved := st.Config["recording-dir"]
	if saved != "" {
		if o.RecordingDir != "" && o.RecordingDir != saved {
			return fmt.Errorf("recordings already use %s; moving existing recordings needs a separate migration", saved)
		}
		return nil
	}
	path := o.RecordingDir
	fallback := filepath.Join(o.installDir(), "recordings")
	if path == "" && u.Interactive {
		u.Explain("Recording location", "Choose a dedicated folder on local storage. For a separate local drive, mount it before setup. This choice does not format disks or connect NFS/CIFS shares.")
		var err error
		path, err = u.Line("Recording directory", fallback)
		if err != nil {
			return err
		}
	}
	if path == "" {
		path = fallback
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, " \t\r\n\"'\\:$%") {
		return fmt.Errorf("use an absolute recording directory without spaces or special characters")
	}
	if path != fallback {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("recording directory %s already exists; choose a new dedicated subdirectory so existing files and permissions stay unchanged", path)
		} else if !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(path)
		real, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return fmt.Errorf("recording parent directory must already exist: %w", err)
		}
		if real != parent {
			return fmt.Errorf("recording parent directory must not use symbolic links")
		}
	}
	st.Config["recording-dir"] = path
	u.Say("Recordings will be stored in %s. The storage budget is chosen in Manage recordings.", path)
	return nil
}
