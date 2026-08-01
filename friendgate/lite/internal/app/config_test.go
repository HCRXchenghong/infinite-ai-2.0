package app

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadConfigTightensExistingDataDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX data-directory permissions are not available on Windows")
	}

	parent := t.TempDir()
	dataDir := filepath.Join(parent, "existing-data")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatalf("create permissive data directory: %v", err)
	}

	t.Setenv("LITE_DATA_DIR", dataDir)
	t.Setenv("LITE_ADMIN_PASSWORD", "temporary-test-password")
	t.Setenv("LITE_MASTER_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("LITE_TRUSTED_PROXIES", "")

	if _, err := LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("stat secured data directory: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("data directory permissions = %04o, want 0700", got)
	}
}
