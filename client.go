package vaultwardensecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type vaultwardenClient struct {
	baseURL    string
	httpClient *http.Client
}

func newVaultwardenClient(baseURL string) *vaultwardenClient {
	return &vaultwardenClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// tokenResponse is the OAuth2 token endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// profileResponse mirrors the Vaultwarden /api/accounts/profile response.
type profileResponse struct {
	ID             string       `json:"id"`
	Email          string       `json:"email"`
	Key            string       `json:"key"`
	PrivateKey     string       `json:"privateKey"`
	Kdf            int          `json:"kdf"`
	KdfIterations  int          `json:"kdfIterations"`
	KdfMemory      *int         `json:"kdfMemory"`
	KdfParallelism *int         `json:"kdfParallelism"`
	Organizations  []orgProfile `json:"organizations"`
}

type orgProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

// cipherItem mirrors a Vaultwarden cipher from /api/ciphers.
type cipherItem struct {
	ID             string        `json:"id"`
	OrganizationID *string       `json:"organizationId"`
	FolderID       *string       `json:"folderId"`
	Type           int           `json:"type"`
	Name           string        `json:"name"`
	Notes          *string       `json:"notes"`
	Key            *string       `json:"key"`
	Login          *loginData    `json:"login"`
	Card           *cardData     `json:"card"`
	Identity       *identityData `json:"identity"`
	SecureNote     *secureNote   `json:"secureNote"`
	Fields         []fieldData   `json:"fields"`
	RevisionDate   string        `json:"revisionDate"`
	CreationDate   string        `json:"creationDate"`
	DeletedDate    *string       `json:"deletedDate"`
}

type loginData struct {
	Username *string   `json:"username"`
	Password *string   `json:"password"`
	Totp     *string   `json:"totp"`
	Uris     []uriData `json:"uris"`
}

type uriData struct {
	URI   string `json:"uri"`
	Match *int   `json:"match"`
}

type cardData struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

type identityData struct {
	Title          *string `json:"title"`
	FirstName      *string `json:"firstName"`
	MiddleName     *string `json:"middleName"`
	LastName       *string `json:"lastName"`
	Address1       *string `json:"address1"`
	Address2       *string `json:"address2"`
	Address3       *string `json:"address3"`
	City           *string `json:"city"`
	State          *string `json:"state"`
	PostalCode     *string `json:"postalCode"`
	Country        *string `json:"country"`
	Company        *string `json:"company"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	SSN            *string `json:"ssn"`
	Username       *string `json:"username"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
}

type secureNote struct {
	Type int `json:"type"`
}

type fieldData struct {
	Name  *string `json:"name"`
	Value *string `json:"value"`
	Type  int     `json:"type"` // 0=text, 1=hidden, 2=boolean, 3=linked
}

// authenticate obtains a Vaultwarden access token via the client_credentials grant.
// Returns the access token string and its TTL in seconds.
func (c *vaultwardenClient) authenticate(ctx context.Context, clientID, clientSecret string) (string, int, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", "api")
	form.Set("deviceType", "21")
	form.Set("deviceIdentifier", "vault-vaultwarden-plugin")
	form.Set("deviceName", "vault-vaultwarden-plugin")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/identity/connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("vaultwarden auth: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	var tr tokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return "", 0, fmt.Errorf("vaultwarden auth: parse response (status %d): %w", resp.StatusCode, err)
	}
	if tr.Error != "" {
		return "", 0, fmt.Errorf("vaultwarden auth: %s: %s", tr.Error, tr.Description)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		return "", 0, fmt.Errorf("vaultwarden auth: unexpected status %d", resp.StatusCode)
	}

	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = 3600
	}
	return tr.AccessToken, ttl, nil
}

// getProfile fetches the user profile, including KDF parameters and encrypted symmetric key.
func (c *vaultwardenClient) getProfile(ctx context.Context, token string) (*profileResponse, error) {
	var profile profileResponse
	if err := c.apiGet(ctx, token, "/api/accounts/profile", &profile); err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}
	return &profile, nil
}

// listCiphers fetches all ciphers the user has access to.
func (c *vaultwardenClient) listCiphers(ctx context.Context, token string) ([]cipherItem, error) {
	var result struct {
		Data   []cipherItem `json:"data"`
		Object string       `json:"object"`
	}
	if err := c.apiGet(ctx, token, "/api/ciphers", &result); err != nil {
		return nil, fmt.Errorf("list ciphers: %w", err)
	}
	return result.Data, nil
}

// getCipher fetches a single cipher by ID.
func (c *vaultwardenClient) getCipher(ctx context.Context, token, id string) (*cipherItem, error) {
	var item cipherItem
	if err := c.apiGet(ctx, token, "/api/ciphers/"+id, &item); err != nil {
		return nil, fmt.Errorf("get cipher %s: %w", id, err)
	}
	return &item, nil
}

func (c *vaultwardenClient) apiGet(ctx context.Context, token, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("not found")
	}
	if resp.StatusCode != http.StatusOK {
		// Try to extract a Bitwarden error message.
		var errResp struct {
			Message          string              `json:"message"`
			Object           string              `json:"object"`
			ValidationErrors map[string][]string `json:"validationErrors"`
		}
		if json.Unmarshal(data, &errResp) == nil && errResp.Message != "" {
			return fmt.Errorf("API error (status %d): %s", resp.StatusCode, errResp.Message)
		}
		return fmt.Errorf("API error: status %d: %s", resp.StatusCode, truncate(string(data), 200))
	}

	// The profile endpoint returns a flat object; the cipher list returns {"data":[...]}.
	// Both cases can be handled by decoding into `out` directly.
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
