package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Archive retires a successfully removed deployment without losing its audit
// record or encrypted recovery export. Callers must first establish that no
// active deployment resources or retained application data remain.
func (s *Store) Archive(st *State) (string, error) {
	if st.Config == nil {
		st.Config = map[string]string{}
	}
	name := st.Config["teardown-archive"]
	if name == "" {
		path, err := os.MkdirTemp(s.dir, "archive-")
		if err != nil {
			return "", err
		}
		name = filepath.Base(path)
		st.Config["teardown-archive"] = name
		// Record intent before moving anything. A retry uses this same directory.
		if err := s.Save(st); err != nil {
			return "", err
		}
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, "archive-") {
		return "", fmt.Errorf("invalid teardown archive directory")
	}
	path := filepath.Join(s.dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("teardown archive must be a private directory")
	}
	recovery := filepath.Join(s.dir, "recovery")
	if _, err := os.Lstat(recovery); err == nil {
		if err := os.Rename(recovery, filepath.Join(path, "recovery")); err != nil {
			return "", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(s.path(), filepath.Join(path, "state.json")); err != nil {
		return "", err
	}
	for _, dir := range []string{path, s.dir} {
		if f, err := os.Open(dir); err == nil {
			f.Sync()
			f.Close()
		}
	}
	return path, nil
}
