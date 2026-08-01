package app

import (
	"path/filepath"
	"testing"
)

func TestSystemMetricsExposeAvailabilityAndScope(t *testing.T) {
	server, _ := testApp(t)
	metrics := server.systemMetrics()
	for _, name := range []string{"cpu", "memory", "storage"} {
		metric, ok := metrics[name].(map[string]any)
		if !ok {
			t.Fatalf("%s metric has unexpected type: %#v", name, metrics[name])
		}
		if _, ok := metric["available"].(bool); !ok {
			t.Fatalf("%s metric does not expose availability: %#v", name, metric)
		}
		if scope, ok := metric["scope"].(string); !ok || scope == "" {
			t.Fatalf("%s metric does not expose scope: %#v", name, metric)
		}
	}
}

func TestReadStorageReportsUnavailableInsteadOfZeroMetric(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-data-directory")
	if total, used, err := readStorage(missing); err == nil || total != 0 || used != 0 {
		t.Fatalf("readStorage(%q) total=%d used=%d err=%v", missing, total, used, err)
	}
}
