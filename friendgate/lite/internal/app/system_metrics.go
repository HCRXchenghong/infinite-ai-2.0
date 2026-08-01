package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

type cpuTimes struct {
	total uint64
	idle  uint64
}

func (s *Server) systemMetrics() map[string]any {
	cpuPercent := 0.0
	cpuAvailable := false
	cpuError := ""
	if current, err := readCPUTimes(); err == nil {
		s.metricsMu.Lock()
		previous := s.lastCPU
		s.lastCPU = current
		s.metricsMu.Unlock()
		if current.total > previous.total {
			totalDelta := current.total - previous.total
			idleDelta := uint64(0)
			if current.idle >= previous.idle {
				idleDelta = current.idle - previous.idle
			}
			if idleDelta <= totalDelta {
				cpuPercent = float64(totalDelta-idleDelta) * 100 / float64(totalDelta)
				cpuAvailable = true
			}
		}
		if !cpuAvailable {
			cpuError = "cpu_sample_unavailable"
		}
	} else {
		cpuError = "proc_stat_unavailable"
	}
	memoryTotal, memoryAvailable, memoryErr := readMemory()
	memoryUsed := uint64(0)
	if memoryTotal >= memoryAvailable {
		memoryUsed = memoryTotal - memoryAvailable
	}
	storagePath := s.cfg.DataDir
	if strings.TrimSpace(storagePath) == "" {
		storagePath = filepath.Dir(s.cfg.DatabasePath)
	}
	storageTotal, storageUsed, storageErr := readStorage(storagePath)
	cpuMetric := map[string]any{
		"percent":   roundMetric(cpuPercent),
		"cores":     runtime.NumCPU(),
		"available": cpuAvailable,
		"scope":     "host",
	}
	if cpuError != "" {
		cpuMetric["error"] = cpuError
	}
	memoryMetric := resourceMetric(memoryUsed, memoryTotal)
	memoryMetric["available"] = memoryErr == nil
	memoryMetric["scope"] = "host"
	if memoryErr != nil {
		memoryMetric["error"] = "proc_meminfo_unavailable"
	}
	storageMetric := resourceMetric(storageUsed, storageTotal)
	storageMetric["available"] = storageErr == nil
	storageMetric["scope"] = "data_filesystem"
	if storageErr != nil {
		storageMetric["error"] = "data_filesystem_unavailable"
	}
	return map[string]any{
		"cpu":     cpuMetric,
		"memory":  memoryMetric,
		"storage": storageMetric,
	}
}

func readCPUTimes() (cpuTimes, error) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, os.ErrInvalid
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		value, parseErr := strconv.ParseUint(field, 10, 64)
		if parseErr != nil {
			return cpuTimes{}, parseErr
		}
		values = append(values, value)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return cpuTimes{total: total, idle: idle}, nil
}

func readMemory() (total, available uint64, err error) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	foundTotal, foundAvailable := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = value * 1024
			foundTotal = true
		case "MemAvailable":
			available = value * 1024
			foundAvailable = true
		}
	}
	if !foundTotal || !foundAvailable || total == 0 || available > total {
		return 0, 0, os.ErrInvalid
	}
	return total, available, nil
}

func readStorage(path string) (total, used uint64, err error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	total = stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	if total == 0 || available > total {
		return 0, 0, os.ErrInvalid
	}
	if total >= available {
		used = total - available
	}
	return total, used, nil
}

func resourceMetric(used, total uint64) map[string]any {
	percent := 0.0
	if total > 0 {
		percent = float64(used) * 100 / float64(total)
	}
	return map[string]any{"used_bytes": used, "total_bytes": total, "percent": roundMetric(percent)}
}

func roundMetric(value float64) float64 {
	return float64(int(value*10+0.5)) / 10
}
