package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// PersonalToken represents a user-generated access token
type PersonalToken struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Username     string     `json:"username"`
	Token        string     `json:"token"`
	Permissions  []string   `json:"permissions"`  // e.g., ["pull", "push", "delete"]
	Repositories []string   `json:"repositories"` // Repository patterns, e.g., ["*", "myrepo/*"]
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	LastUsed     *time.Time `json:"last_used,omitempty"`
}

// PersonalTokenStore manages personal access tokens
type PersonalTokenStore struct {
	tokens     map[string]*PersonalToken // token -> PersonalToken
	tokensByID map[string]*PersonalToken // id -> PersonalToken
	filePath   string
	mu         sync.RWMutex
}

// NewPersonalTokenStore creates a new personal token store
func NewPersonalTokenStore(filePath string) (*PersonalTokenStore, error) {
	store := &PersonalTokenStore{
		tokens:     make(map[string]*PersonalToken),
		tokensByID: make(map[string]*PersonalToken),
		filePath:   filePath,
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Load existing tokens
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

// CreateToken creates a new personal access token
func (s *PersonalTokenStore) CreateToken(username, name, description string, permissions, repositories []string, expiresIn *time.Duration) (*PersonalToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate unique token
	token := generateSecureToken()

	// Calculate expiration
	var expiresAt *time.Time
	if expiresIn != nil {
		exp := time.Now().Add(*expiresIn)
		expiresAt = &exp
	}

	pt := &PersonalToken{
		ID:           uuid.New().String(),
		Name:         name,
		Description:  description,
		Username:     username,
		Token:        token,
		Permissions:  permissions,
		Repositories: repositories,
		CreatedAt:    time.Now(),
		ExpiresAt:    expiresAt,
	}

	s.tokens[token] = pt
	s.tokensByID[pt.ID] = pt

	if err := s.save(); err != nil {
		return nil, err
	}

	return pt, nil
}

// GetToken retrieves a token and updates last used time
func (s *PersonalTokenStore) GetToken(token string) (*PersonalToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pt, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}

	// Check if expired
	if pt.ExpiresAt != nil && time.Now().After(*pt.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	// Update last used
	now := time.Now()
	pt.LastUsed = &now

	if err := s.save(); err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to update last used time: %v\n", err)
	}

	return pt, nil
}

// GetTokenByID retrieves a token by its ID
func (s *PersonalTokenStore) GetTokenByID(id string) (*PersonalToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pt, ok := s.tokensByID[id]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}

	return pt, nil
}

// ListTokens returns all tokens for a user
func (s *PersonalTokenStore) ListTokens(username string) []*PersonalToken {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var tokens []*PersonalToken
	for _, pt := range s.tokens {
		if pt.Username == username {
			// Return copy without the actual token value
			tokenCopy := *pt
			tokenCopy.Token = maskToken(pt.Token)
			tokens = append(tokens, &tokenCopy)
		}
	}

	return tokens
}

// DeleteToken deletes a token by ID
func (s *PersonalTokenStore) DeleteToken(id, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pt, ok := s.tokensByID[id]
	if !ok {
		return fmt.Errorf("token not found")
	}

	// Verify ownership
	if pt.Username != username {
		return fmt.Errorf("unauthorized")
	}

	delete(s.tokens, pt.Token)
	delete(s.tokensByID, pt.ID)

	return s.save()
}

// load loads tokens from file
func (s *PersonalTokenStore) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var tokens []*PersonalToken
	if err := json.Unmarshal(data, &tokens); err != nil {
		return err
	}

	for _, pt := range tokens {
		s.tokens[pt.Token] = pt
		s.tokensByID[pt.ID] = pt
	}

	return nil
}

// save saves tokens to file
func (s *PersonalTokenStore) save() error {
	var tokens []*PersonalToken
	for _, pt := range s.tokens {
		tokens = append(tokens, pt)
	}

	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, data, 0600)
}

// generateSecureToken generates a secure random token
func generateSecureToken() string {
	return "pat_" + uuid.New().String() + uuid.New().String()
}

// maskToken masks a token for display
func maskToken(token string) string {
	if len(token) < 16 {
		return "***"
	}
	return token[:8] + "..." + token[len(token)-8:]
}
