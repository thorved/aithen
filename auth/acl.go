package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ACLEntry represents a single access control rule
type ACLEntry struct {
	Match   ACLMatch `json:"match"`
	Actions []string `json:"actions"`
	Comment string   `json:"comment,omitempty"`
}

// ACLMatch defines the matching criteria for an ACL entry
type ACLMatch struct {
	Account string `json:"account,omitempty"` // Username or regex pattern
	Type    string `json:"type,omitempty"`    // Resource type (e.g., "repository")
	Name    string `json:"name,omitempty"`    // Repository name or pattern
}

// ACL manages access control lists
type ACL struct {
	Entries []ACLEntry
}

// NewACL creates a new ACL from a file
func NewACL(filePath string) (*ACL, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ACL file: %v", err)
	}

	var entries []ACLEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse ACL file: %v", err)
	}

	return &ACL{Entries: entries}, nil
}

// GetPermissions returns the allowed actions for a user on a resource
// Uses first-match-wins strategy: if an exact account match is found, only that rule applies
func (a *ACL) GetPermissions(username, resourceType, resourceName string) []string {
	var allowedActions []string
	actionsMap := make(map[string]bool)
	exactMatchFound := false

	// First pass: look for exact account matches (not regex)
	for _, entry := range a.Entries {
		if entry.Match.Account != "" && !isRegexPattern(entry.Match.Account) {
			if entry.Match.Account == username {
				if a.matchesEntry(entry, username, resourceType, resourceName) {
					exactMatchFound = true
					for _, action := range entry.Actions {
						actionsMap[action] = true
					}
					// Found exact match, use only this rule
					break
				}
			}
		}
	}

	// If no exact match, apply all matching regex/wildcard rules
	if !exactMatchFound {
		for _, entry := range a.Entries {
			if a.matchesEntry(entry, username, resourceType, resourceName) {
				for _, action := range entry.Actions {
					actionsMap[action] = true
				}
			}
		}
	}

	for action := range actionsMap {
		allowedActions = append(allowedActions, action)
	}

	return allowedActions
}

// isRegexPattern checks if a pattern is a regex (enclosed in forward slashes)
func isRegexPattern(pattern string) bool {
	return len(pattern) > 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/'
}

// matchesEntry checks if an entry matches the given criteria
func (a *ACL) matchesEntry(entry ACLEntry, username, resourceType, resourceName string) bool {
	// Check account match
	if entry.Match.Account != "" {
		if !a.matchPattern(entry.Match.Account, username) {
			return false
		}
	}

	// Check type match
	if entry.Match.Type != "" && entry.Match.Type != resourceType {
		return false
	}

	// Check name match (repository name)
	if entry.Match.Name != "" {
		if !a.matchPattern(entry.Match.Name, resourceName) {
			return false
		}
	}

	return true
}

// matchPattern matches a string against a pattern (supports wildcards and regex)
func (a *ACL) matchPattern(pattern, value string) bool {
	// Empty username for anonymous
	if pattern == "" && value == "" {
		return true
	}

	// Direct match
	if pattern == value {
		return true
	}

	// Regex pattern (enclosed in /.+/)
	if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		regexPattern := strings.Trim(pattern, "/")
		matched, err := regexp.MatchString(regexPattern, value)
		if err == nil && matched {
			return true
		}
	}

	// Wildcard pattern (convert * to .*)
	if strings.Contains(pattern, "*") {
		wildcardPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		matched, err := regexp.MatchString(wildcardPattern, value)
		if err == nil && matched {
			return true
		}
	}

	// Variable substitution ${account}
	if strings.Contains(pattern, "${account}") {
		expandedPattern := strings.ReplaceAll(pattern, "${account}", value)
		if expandedPattern == value {
			return true
		}
		// Also check if it's a prefix match
		if strings.HasSuffix(expandedPattern, "/*") {
			prefix := strings.TrimSuffix(expandedPattern, "/*")
			if strings.HasPrefix(value, prefix+"/") || value == prefix {
				return true
			}
		}
	}

	return false
}

// CanPull checks if a user can pull from a repository
func (a *ACL) CanPull(username, repo string) bool {
	actions := a.GetPermissions(username, "repository", repo)
	for _, action := range actions {
		if action == "pull" || action == "*" {
			return true
		}
	}
	return false
}

// CanPush checks if a user can push to a repository
func (a *ACL) CanPush(username, repo string) bool {
	actions := a.GetPermissions(username, "repository", repo)
	for _, action := range actions {
		if action == "push" || action == "*" {
			return true
		}
	}
	return false
}
