package auth

import (
	"fmt"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnService handles WebAuthn operations
type WebAuthnService struct {
	webAuthn *webauthn.WebAuthn
	sessions map[string]*webauthn.SessionData // username -> session
	mu       sync.RWMutex
}

// NewWebAuthnService creates a new WebAuthn service
func NewWebAuthnService(rpDisplayName, rpID, rpOrigin string) (*WebAuthnService, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
		// Set timeouts (in milliseconds)
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    60000, // 60 seconds
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    60000, // 60 seconds
			},
		},
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn: %v", err)
	}

	return &WebAuthnService{
		webAuthn: webAuthn,
		sessions: make(map[string]*webauthn.SessionData),
	}, nil
}

// BeginRegistration starts the registration process for a user
func (s *WebAuthnService) BeginRegistration(user *User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	// Use platform authenticator for passkeys (not cross-platform like USB keys)
	authSelection := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.Platform,
		RequireResidentKey:      protocol.ResidentKeyNotRequired(),
		UserVerification:        protocol.VerificationRequired,
	}

	options, session, err := s.webAuthn.BeginRegistration(
		user,
		webauthn.WithAuthenticatorSelection(authSelection),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(user.WebAuthnCredentialDescriptors()),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin registration: %v", err)
	}

	// Store session
	s.mu.Lock()
	s.sessions[user.Username] = session
	s.mu.Unlock()

	return options, session, nil
}

// FinishRegistration completes the registration process
func (s *WebAuthnService) FinishRegistration(user *User, response *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	s.mu.RLock()
	session, exists := s.sessions[user.Username]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found for user")
	}

	credential, err := s.webAuthn.CreateCredential(user, *session, response)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %v", err)
	}

	// Clean up session
	s.mu.Lock()
	delete(s.sessions, user.Username)
	s.mu.Unlock()

	return credential, nil
}

// BeginLogin starts the login/authentication process
func (s *WebAuthnService) BeginLogin(user *User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	options, session, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin login: %v", err)
	}

	// Store session
	s.mu.Lock()
	s.sessions[user.Username] = session
	s.mu.Unlock()

	return options, session, nil
}

// FinishLogin completes the login/authentication process
func (s *WebAuthnService) FinishLogin(user *User, response *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	s.mu.RLock()
	session, exists := s.sessions[user.Username]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found for user")
	}

	credential, err := s.webAuthn.ValidateLogin(user, *session, response)
	if err != nil {
		return nil, fmt.Errorf("failed to validate login: %v", err)
	}

	// Clean up session
	s.mu.Lock()
	delete(s.sessions, user.Username)
	s.mu.Unlock()

	return credential, nil
}

// Note: Discoverable/usernameless login (passkey login without entering username first)
// is not currently implemented. Users must enter their username before using passkey login.
// This could be added in a future enhancement by implementing proper credential-to-user lookup.
