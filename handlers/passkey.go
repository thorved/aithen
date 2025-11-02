package handlers

import (
	"encoding/base64"
	"net/http"

	"aithen/auth"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
)

// BeginPasskeyRegistration starts the passkey registration flow
func (h *Handler) BeginPasskeyRegistration(c *gin.Context) {
	username := auth.GetCurrentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	user, err := h.UserStore.GetUser(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	options, _, err := h.WebAuthnService.BeginRegistration(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin registration: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, options)
}

// FinishPasskeyRegistration completes the passkey registration flow
func (h *Handler) FinishPasskeyRegistration(c *gin.Context) {
	username := auth.GetCurrentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	user, err := h.UserStore.GetUser(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Parse the attestation response
	var ccr protocol.CredentialCreationResponse
	if err := c.ShouldBindJSON(&ccr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	parsedResponse, err := ccr.Parse()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse response"})
		return
	}

	credential, err := h.WebAuthnService.FinishRegistration(user, parsedResponse)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to complete registration: " + err.Error()})
		return
	}

	// Get the passkey name from query params or use default
	passkeyName := c.Query("name")
	if passkeyName == "" {
		passkeyName = "Passkey"
	}

	// Save the credential
	if err := h.UserStore.AddPasskey(username, credential, passkeyName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save passkey"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Passkey registered successfully"})
}

// BeginPasskeyLogin starts the passkey login flow
func (h *Handler) BeginPasskeyLogin(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}

	user, err := h.UserStore.GetUser(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check if user has any passkeys
	if user.Passkeys == nil || len(user.Passkeys.Credentials) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No passkeys registered for this user"})
		return
	}

	options, _, err := h.WebAuthnService.BeginLogin(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin login: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, options)
}

// FinishPasskeyLogin completes the passkey login flow
func (h *Handler) FinishPasskeyLogin(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}

	user, err := h.UserStore.GetUser(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Parse the assertion response
	var car protocol.CredentialAssertionResponse
	if err := c.ShouldBindJSON(&car); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	parsedResponse, err := car.Parse()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse response"})
		return
	}

	credential, err := h.WebAuthnService.FinishLogin(user, parsedResponse)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to complete login: " + err.Error()})
		return
	}

	// Update last used timestamp
	if err := h.UserStore.UpdatePasskeyLastUsed(username, credential.ID); err != nil {
		// Non-fatal error, just log it
		c.Writer.Header().Add("X-Warning", "Failed to update passkey last used timestamp")
	}

	// Create session and store credentials
	session := sessions.Default(c)
	session.Set(auth.SessionUserKey, username)
	// Note: With passkey login, we don't have a password, so we don't store it
	// This means registry API calls will need to use personal tokens instead
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Login successful"})
}

// ListPasskeys returns all passkeys for the current user
func (h *Handler) ListPasskeys(c *gin.Context) {
	username := auth.GetCurrentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	user, err := h.UserStore.GetUser(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.Passkeys == nil || len(user.Passkeys.Credentials) == 0 {
		c.JSON(http.StatusOK, gin.H{"passkeys": []interface{}{}})
		return
	}

	// Build a safe response (don't expose private keys)
	passkeys := make([]gin.H, len(user.Passkeys.Credentials))
	for i, cred := range user.Passkeys.Credentials {
		passkeys[i] = gin.H{
			"id":           base64.URLEncoding.EncodeToString(cred.ID),
			"name":         cred.Name,
			"created_at":   cred.CreatedAt,
			"last_used_at": cred.LastUsedAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{"passkeys": passkeys})
}

// DeletePasskey removes a passkey from the current user
func (h *Handler) DeletePasskey(c *gin.Context) {
	username := auth.GetCurrentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	credentialIDStr := c.Param("id")
	if credentialIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Credential ID is required"})
		return
	}

	// Decode base64 credential ID
	credentialID, err := base64.URLEncoding.DecodeString(credentialIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid credential ID format"})
		return
	}

	if err := h.UserStore.RemovePasskey(username, credentialID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete passkey: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Passkey deleted successfully"})
}

// ShowPasskeysPage renders the passkeys management page
func (h *Handler) ShowPasskeysPage(c *gin.Context) {
	username := auth.GetCurrentUser(c)
	c.HTML(http.StatusOK, "passkeys.html", gin.H{
		"Username": username,
	})
}

// UpdatePasskeyName updates the name of a passkey
func (h *Handler) UpdatePasskeyName(c *gin.Context) {
	username := auth.GetCurrentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	credentialIDStr := c.Param("id")
	if credentialIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Credential ID is required"})
		return
	}

	// Decode base64 credential ID
	credentialID, err := base64.URLEncoding.DecodeString(credentialIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid credential ID format"})
		return
	}

	var req struct {
		Name string `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := h.UserStore.UpdatePasskeyName(username, credentialID, req.Name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update passkey name: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Passkey name updated successfully"})
}
