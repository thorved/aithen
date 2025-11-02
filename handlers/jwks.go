package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// JWKSHandler handles JWKS requests
func (h *Handler) JWKSHandler(c *gin.Context) {
	jwks := h.TokenService.GetJWKS()
	c.JSON(http.StatusOK, jwks)
}
