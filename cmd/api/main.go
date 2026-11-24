package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"

	"github.com/fabricio948/system_login/internal/config"
	"github.com/fabricio948/system_login/internal/handler"
	"github.com/fabricio948/system_login/internal/httpx"
	"github.com/fabricio948/system_login/internal/middleware"
	"github.com/fabricio948/system_login/internal/repository"
	"github.com/fabricio948/system_login/internal/service"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if err := run(logger); err != nil {
		logger.Error("api stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	db, err := openDatabase(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	recoveryRepo := repository.NewPasswordRecoveryRepository(db)

	hasher := service.NewBcryptHasher(bcrypt.DefaultCost)
	notifier := service.NewLogNotificationService(logger)
	publisher := service.NewLogEventPublisher(logger)
	clock := service.NewSystemClock()

	authService := service.NewAuthService(
		cfg,
		userRepo,
		sessionRepo,
		recoveryRepo,
		hasher,
		notifier,
		publisher,
		clock,
	)
	accountService := service.NewAccountService(
		userRepo,
		sessionRepo,
		hasher,
		publisher,
		clock,
	)

	authHandler := handler.NewAuthHandler(authService, logger)
	accountHandler := handler.NewAccountHandler(accountService, logger)
	authMiddleware := middleware.Authentication(authService, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", authHandler.Register)
	mux.HandleFunc("POST /auth/login", authHandler.Login)
	mux.HandleFunc("POST /auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /auth/password/forgot", authHandler.ForgotPassword)
	mux.HandleFunc("POST /auth/password/reset", authHandler.ResetPassword)

	mux.Handle("POST /auth/logout", authMiddleware(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("GET /users/me", authMiddleware(http.HandlerFunc(accountHandler.GetProfile)))
	mux.Handle("PATCH /users/me/name", authMiddleware(http.HandlerFunc(accountHandler.UpdateName)))
	mux.Handle("POST /users/me/change-password", authMiddleware(http.HandlerFunc(accountHandler.ChangePassword)))
	mux.Handle("DELETE /users/me", authMiddleware(http.HandlerFunc(accountHandler.DeleteAccount)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSONError(w, http.StatusNotFound, "not_found", "route not found")
	})

	root := middleware.Recovery(logger)(middleware.CORS(cfg.CORSAllowedOrigin)(mux))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.AppPort),
		Handler:           root,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("api started", "port", cfg.AppPort, "env", cfg.AppEnv)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve http: %w", err)
	case <-shutdownSignal.Done():
		logger.Info("shutting down api")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown http server: %w", err)
		}
		return nil
	}
}

func openDatabase(cfg *config.Config) (*sql.DB, error) {
	connector, err := mysql.NewConnector(cfg.MySQLConfig())
	if err != nil {
		return nil, fmt.Errorf("create mysql connector: %w", err)
	}

	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping mysql: %w", err)
	}
	return db, nil
}
