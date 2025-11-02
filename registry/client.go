package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client represents a Docker Registry v2 API client
type Client struct {
	baseURL  string
	username string
	password string
	client   *http.Client
}

// Repository represents a registry repository
type Repository struct {
	Name string `json:"name"`
}

// Tag represents an image tag
type Tag struct {
	Name string `json:"name"`
}

// Manifest represents image manifest information
type Manifest struct {
	SchemaVersion int                    `json:"schemaVersion"`
	MediaType     string                 `json:"mediaType"`
	Config        ManifestConfig         `json:"config"`
	Layers        []ManifestLayer        `json:"layers"`
	Architecture  string                 `json:"architecture,omitempty"`
	OS            string                 `json:"os,omitempty"`
	RawData       map[string]interface{} `json:"-"`
	// OCI-specific fields
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// ManifestConfig represents the config in a manifest
type ManifestConfig struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// ManifestLayer represents a layer in a manifest
type ManifestLayer struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// ImageInfo represents detailed image information
type ImageInfo struct {
	Repository   string
	Tag          string
	Digest       string
	Size         int64
	Layers       int
	Architecture string
	CreatedAt    time.Time
}

// NewClient creates a new registry client
func NewClient(baseURL, username, password string) *Client {
	return &Client{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		username: username,
		password: password,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// doRequest performs an HTTP request with authentication
func (c *Client) doRequest(method, path string, acceptHeader string) (*http.Response, error) {
	url := c.baseURL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	if acceptHeader != "" {
		req.Header.Set("Accept", acceptHeader)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// ListRepositories returns all repositories in the registry
func (c *Client) ListRepositories() ([]string, error) {
	resp, err := c.doRequest("GET", "/v2/_catalog", "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Repositories []string `json:"repositories"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Repositories, nil
}

// ListTags returns all tags for a repository
func (c *Client) ListTags(repository string) ([]string, error) {
	path := fmt.Sprintf("/v2/%s/tags/list", repository)
	resp, err := c.doRequest("GET", path, "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Tags, nil
}

// GetManifest retrieves the manifest for a specific image tag
func (c *Client) GetManifest(repository, tag string) (*Manifest, string, error) {
	path := fmt.Sprintf("/v2/%s/manifests/%s", repository, tag)

	// Accept both OCI and Docker v2 manifest formats
	// Registry v3 uses OCI format by default
	acceptHeader := "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.docker.distribution.manifest.list.v2+json"
	resp, err := c.doRequest("GET", path, acceptHeader)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("registry API error: %d - %s", resp.StatusCode, string(body))
	}

	// Get the digest from the header
	digest := resp.Header.Get("Docker-Content-Digest")

	var manifest Manifest
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, "", err
	}

	// Handle both OCI and Docker manifest formats
	// Set default values if not present
	if manifest.Architecture == "" {
		// Try to parse from raw data if available
		var rawManifest map[string]interface{}
		if err := json.Unmarshal(body, &rawManifest); err == nil {
			if config, ok := rawManifest["config"].(map[string]interface{}); ok {
				if arch, ok := config["architecture"].(string); ok {
					manifest.Architecture = arch
				}
			}
		}
	}

	return &manifest, digest, nil
}

// GetImageInfo retrieves detailed information about an image
func (c *Client) GetImageInfo(repository, tag string) (*ImageInfo, error) {
	manifest, digest, err := c.GetManifest(repository, tag)
	if err != nil {
		return nil, err
	}

	var totalSize int64
	for _, layer := range manifest.Layers {
		totalSize += layer.Size
	}

	// Get architecture from manifest or fetch from config blob
	architecture := manifest.Architecture
	if architecture == "" && manifest.Config.Digest != "" {
		// Try to fetch architecture from config blob
		configInfo, err := c.GetBlobConfig(repository, manifest.Config.Digest)
		if err == nil && configInfo != nil {
			architecture = configInfo.Architecture
		}
	}

	info := &ImageInfo{
		Repository:   repository,
		Tag:          tag,
		Digest:       digest,
		Size:         totalSize,
		Layers:       len(manifest.Layers),
		Architecture: architecture,
		CreatedAt:    time.Now(), // Would need to parse from config blob
	}

	return info, nil
}

// BlobConfig represents the configuration from a config blob
type BlobConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Created      string `json:"created"`
}

// GetBlobConfig retrieves and parses a config blob
func (c *Client) GetBlobConfig(repository, digest string) (*BlobConfig, error) {
	path := fmt.Sprintf("/v2/%s/blobs/%s", repository, digest)
	resp, err := c.doRequest("GET", path, "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch config blob: %d", resp.StatusCode)
	}

	var config BlobConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// DeleteImage deletes an image by its digest
func (c *Client) DeleteImage(repository, digest string) error {
	path := fmt.Sprintf("/v2/%s/manifests/%s", repository, digest)
	resp, err := c.doRequest("DELETE", path, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete image: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// CheckHealth checks if the registry is accessible
func (c *Client) CheckHealth() error {
	resp, err := c.doRequest("GET", "/v2/", "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry health check failed: %d", resp.StatusCode)
	}

	return nil
}
