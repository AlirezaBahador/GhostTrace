// ghosttrace-server is a read-only API over recorded JSONL, not the kernel agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AlirezaBahador/GhostTrace/internal/api"
)

func run() int {
	listen := flag.String("listen", "127.0.0.1:7766", "loopback listener (remote binding disallowed)")
	input := flag.String("events", "events.jsonl", "recorded JSONL file")
	rules := flag.String("rules", "", "optional YAML rule directory/file")
	dashboardDir := flag.String("dashboard-dir", "", "optional built React dashboard/dist directory")
	tokenEnv := flag.String("token-env", "GHOSTTRACE_API_TOKEN", "environment variable containing the required Bearer token")
	allowDevNoAuth := flag.Bool("allow-unauthenticated-loopback", false, "explicit INSECURE local development only; all local users can access telemetry")
	maxFileMB := flag.Int64("max-file-mb", 64, "maximum recorded file size (1..1024 MiB)")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !(host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())) {
		fmt.Fprintln(os.Stderr, "ghosttrace-server: --listen must specify a loopback IP address (or localhost)")
		return 2
	}
	if *maxFileMB < 1 || *maxFileMB > 1024 {
		fmt.Fprintln(os.Stderr, "ghosttrace-server: max-file-mb must be 1..1024")
		return 2
	}
	token := os.Getenv(*tokenEnv)
	if err := validateAuth(token, *allowDevNoAuth); err != nil {
		fmt.Fprintln(os.Stderr, "ghosttrace-server:", err)
		return 2
	}
	handler, err := api.New(*input, *rules, token, *maxFileMB<<20)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ghosttrace-server:", err)
		return 2
	}
	var httpHandler http.Handler = handler
	if *dashboardDir != "" {
		indexPath := filepath.Join(*dashboardDir, "index.html")
		info, err := os.Stat(indexPath)
		if err != nil || !info.Mode().IsRegular() {
			fmt.Fprintln(os.Stderr, "ghosttrace-server: dashboard-dir requires a built index.html")
			return 2
		}
		router := http.NewServeMux()
		router.Handle("/api/", handler)
		router.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			http.FileServer(http.Dir(*dashboardDir)).ServeHTTP(w, r)
		}))
		httpHandler = router
	}
	server := &http.Server{Addr: *listen, Handler: httpHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 0, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	// Streaming responses use a bounded 10-minute lifetime. All other API
	// operations are context-cancelled when clients disconnect.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdown := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		close(shutdown)
	}()
	slog.Info("read-only GhostTrace API started", "listen", *listen, "source", "recorded_jsonl")
	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failure", "error", err)
		return 1
	}
	// Explicitly wait for shutdown to finish before reporting success.
	if ctx.Err() != nil {
		<-shutdown
	}
	return 0
}
func validateAuth(token string, allowDevNoAuth bool) error {
	if token == "" && !allowDevNoAuth {
		return fmt.Errorf("API token is required; supply GHOSTTRACE_API_TOKEN in a protected environment, or explicitly opt into insecure local development with -allow-unauthenticated-loopback")
	}
	if len(token) > 4096 || (len(token) > 0 && len(token) < 16) {
		return fmt.Errorf("token length must be 16..4096 bytes")
	}
	return nil
}

func main() { os.Exit(run()) }
