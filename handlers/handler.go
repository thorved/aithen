package handlers

import (
	"registry-webui/auth"
	"registry-webui/config"
	"registry-webui/registry"
)

// Handler contains all dependencies for HTTP handlers
type Handler struct {
	Config       *config.Config
	Auth         *auth.HtpasswdAuth
	Registry     *registry.Client
	TokenService *auth.TokenService
	TokenStore   *auth.PersonalTokenStore
}

// NewHandler creates a new handler instance
func NewHandler(cfg *config.Config, authHandler *auth.HtpasswdAuth, registryClient *registry.Client, tokenService *auth.TokenService, tokenStore *auth.PersonalTokenStore) *Handler {
	return &Handler{
		Config:       cfg,
		Auth:         authHandler,
		Registry:     registryClient,
		TokenService: tokenService,
		TokenStore:   tokenStore,
	}
}
