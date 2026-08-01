package main

import (
	"log/slog"
	"os"

	"github.com/HCRXchenghong/api-codex/lite/internal/app"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := app.RunMain(); err != nil {
		slog.Error("friendgate stopped", "error", err)
		os.Exit(1)
	}
}
