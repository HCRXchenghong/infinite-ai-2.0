package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/HCRXchenghong/api-codex/lite/internal/app"
)

func main() {
	apply := flag.Bool("apply", false, "write the verified legacy snapshot into PostgreSQL; stop the server first")
	timeout := flag.Duration("timeout", 20*time.Minute, "maximum import duration")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, err := app.RunLegacyPlatformImport(ctx, *apply)
	if err != nil {
		fmt.Fprintln(os.Stderr, "migration failed:", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode migration report:", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}
