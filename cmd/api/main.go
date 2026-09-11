package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sharanrprasad/iam-service/internal/app"
	"github.com/sharanrprasad/iam-service/internal/handler"
)

func main() {
	cfg := app.Load()

	a, err := app.New(cfg)
	if err != nil {
		log.Fatalf("app.New: %v", err)
	}
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			log.Printf("app.Close: %v", closeErr)
		}
	}()

	authHandler := handler.NewAuthHandler(a.Auth, a.Clients, a.TokenGrants, cfg.CookieSecure, cfg.LoginURL)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	r.Post("/login", authHandler.Login)
	r.Post("/logout", authHandler.Logout)
	r.Post("/refresh", authHandler.Refresh)

	r.Route("/oauth", func(r chi.Router) {
		r.Get("/authorize", authHandler.Authorize)
		r.Post("/token", authHandler.Token)
	})

	r.Route("/admin", func(r chi.Router) {
		r.Post("/clients", authHandler.RegisterClient)
	})

	srv := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("server listening on %s", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	<-done
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("server shutdown: %v", err)
	}
	log.Println("server stopped")
}
