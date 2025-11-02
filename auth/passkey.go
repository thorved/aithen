package auth

import (
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Credential represents a WebAuthn credential (passkey)
type Credential struct {
	ID              []byte                     `json:"id"`
	PublicKey       []byte                     `json:"public_key"`
	AttestationType string                     `json:"attestation_type"`
	Transport       []protocol.AuthenticatorTransport `json:"transport"`
	Flags           webauthn.CredentialFlags   `json:"flags"`
	Authenticator   webauthn.Authenticator     `json:"authenticator"`
	Name            string                     `json:"name"`           // User-friendly name for the passkey
	CreatedAt       time.Time                  `json:"created_at"`
	LastUsedAt      time.Time                  `json:"last_used_at"`
}

// PasskeyCredentials holds all credentials for a user
type PasskeyCredentials struct {
	UserID      []byte        `json:"user_id"`
	Credentials []*Credential `json:"credentials"`
}

// AddCredential adds a new credential to user's passkeys
func (u *User) AddCredential(credential *Credential) {
	if u.Passkeys == nil {
		u.Passkeys = &PasskeyCredentials{
			UserID:      []byte(u.Username),
			Credentials: []*Credential{},
		}
	}
	u.Passkeys.Credentials = append(u.Passkeys.Credentials, credential)
}

// GetCredentialByID retrieves a credential by its ID
func (u *User) GetCredentialByID(id []byte) *Credential {
	if u.Passkeys == nil {
		return nil
	}
	for _, cred := range u.Passkeys.Credentials {
		if len(cred.ID) == len(id) {
			match := true
			for i := range cred.ID {
				if cred.ID[i] != id[i] {
					match = false
					break
				}
			}
			if match {
				return cred
			}
		}
	}
	return nil
}

// UpdateCredentialLastUsed updates the last used timestamp for a credential
func (u *User) UpdateCredentialLastUsed(id []byte) {
	if cred := u.GetCredentialByID(id); cred != nil {
		cred.LastUsedAt = time.Now()
	}
}

// RemoveCredential removes a credential by its ID
func (u *User) RemoveCredential(id []byte) bool {
	if u.Passkeys == nil {
		return false
	}
	for i, cred := range u.Passkeys.Credentials {
		if len(cred.ID) == len(id) {
			match := true
			for j := range cred.ID {
				if cred.ID[j] != id[j] {
					match = false
					break
				}
			}
			if match {
				u.Passkeys.Credentials = append(u.Passkeys.Credentials[:i], u.Passkeys.Credentials[i+1:]...)
				return true
			}
		}
	}
	return false
}

// WebAuthnID implements webauthn.User interface
func (u *User) WebAuthnID() []byte {
	return []byte(u.Username)
}

// WebAuthnName implements webauthn.User interface
func (u *User) WebAuthnName() string {
	return u.Username
}

// WebAuthnDisplayName implements webauthn.User interface
func (u *User) WebAuthnDisplayName() string {
	if u.FullName != "" {
		return u.FullName
	}
	return u.Username
}

// WebAuthnCredentials implements webauthn.User interface
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	if u.Passkeys == nil {
		return []webauthn.Credential{}
	}
	
	credentials := make([]webauthn.Credential, len(u.Passkeys.Credentials))
	for i, cred := range u.Passkeys.Credentials {
		credentials[i] = webauthn.Credential{
			ID:              cred.ID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Transport:       cred.Transport,
			Flags:           cred.Flags,
			Authenticator:   cred.Authenticator,
		}
	}
	return credentials
}

// WebAuthnCredentialDescriptors returns credential descriptors for exclusion
func (u *User) WebAuthnCredentialDescriptors() []protocol.CredentialDescriptor {
	if u.Passkeys == nil {
		return []protocol.CredentialDescriptor{}
	}
	
	descriptors := make([]protocol.CredentialDescriptor, len(u.Passkeys.Credentials))
	for i, cred := range u.Passkeys.Credentials {
		descriptors[i] = protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    cred.ID,
			Transport:       cred.Transport,
		}
	}
	return descriptors
}

// WebAuthnIcon implements webauthn.User interface (optional)
func (u *User) WebAuthnIcon() string {
	return ""
}

// AddPasskey adds a new passkey to a user
func (s *UserStore) AddPasskey(username string, credential *webauthn.Credential, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return fmt.Errorf("user not found")
	}

	// Create credential with metadata
	cred := &Credential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transport:       credential.Transport,
		Flags:           credential.Flags,
		Authenticator:   credential.Authenticator,
		Name:            name,
		CreatedAt:       time.Now(),
		LastUsedAt:      time.Now(),
	}

	user.AddCredential(cred)
	user.UpdatedAt = time.Now()

	return s.save()
}

// RemovePasskey removes a passkey from a user
func (s *UserStore) RemovePasskey(username string, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return fmt.Errorf("user not found")
	}

	if !user.RemoveCredential(credentialID) {
		return fmt.Errorf("credential not found")
	}

	user.UpdatedAt = time.Now()
	return s.save()
}

// UpdatePasskeyLastUsed updates the last used timestamp for a passkey
func (s *UserStore) UpdatePasskeyLastUsed(username string, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return fmt.Errorf("user not found")
	}

	user.UpdateCredentialLastUsed(credentialID)
	user.UpdatedAt = time.Now()

	return s.save()
}

// UpdatePasskeyName updates the name of a passkey
func (s *UserStore) UpdatePasskeyName(username string, credentialID []byte, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return fmt.Errorf("user not found")
	}

	cred := user.GetCredentialByID(credentialID)
	if cred == nil {
		return fmt.Errorf("credential not found")
	}

	cred.Name = name
	user.UpdatedAt = time.Now()

	return s.save()
}

// GetUserByCredentialID finds a user by their credential ID
func (s *UserStore) GetUserByCredentialID(credentialID []byte) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.GetCredentialByID(credentialID) != nil {
			return user, nil
		}
	}

	return nil, fmt.Errorf("user not found for credential")
}
