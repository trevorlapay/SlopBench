// Command catalogd serves the SlopShop product catalogue.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/slopshop/catalog/internal/httpapi"
	"github.com/slopshop/catalog/internal/store"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 90 * time.Second
	shutdownGrace     = 20 * time.Second
	minServiceToken   = 32
)

func requiredEnv(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", errors.New("missing required environment variable: " + name)
	}
	return value, nil
}

func run(ctx context.Context, log *slog.Logger) error {
	dsn, err := requiredEnv("CATALOG_DATABASE_URL")
	if err != nil {
		return err
	}

	token, err := requiredEnv("CATALOG_SERVICE_TOKEN")
	if err != nil {
		return err
	}
	if len(token) < minServiceToken {
		return errors.New("CATALOG_SERVICE_TOKEN must be at least 32 bytes")
	}

	db, err := store.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	addr := os.Getenv("CATALOG_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8081"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           httpapi.NewServer(db, []byte(token), log).Routes(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("catalogd listening", slog.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("catalogd shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log); err != nil {
		log.Error("catalogd exited", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
