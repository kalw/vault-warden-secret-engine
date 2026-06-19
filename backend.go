package vaultwardensecrets

import (
	"context"
	"crypto/rsa"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory is the entry point for the Vault plugin.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type vaultwardenBackend struct {
	*framework.Backend

	mu sync.Mutex

	// Cached Vaultwarden access token.
	accessToken       string
	accessTokenExpiry time.Time

	// Cached user and org keys, derived on first item read.
	keys *derivedKeys
}

// derivedKeys holds decrypted symmetric keys for the user and all accessible orgs.
type derivedKeys struct {
	userEncKey []byte // 32-byte AES-256 key
	userMacKey []byte // 32-byte HMAC-SHA256 key
	rsaKey     *rsa.PrivateKey
	orgKeys    map[string]*symKey // orgID → org enc/mac keys
}

type symKey struct {
	encKey []byte
	macKey []byte
}

func (d *derivedKeys) keyForCipher(orgID string) (encKey, macKey []byte) {
	if orgID != "" {
		if ok := d.orgKeys[orgID]; ok != nil {
			return ok.encKey, ok.macKey
		}
	}
	return d.userEncKey, d.userMacKey
}

func newBackend() *vaultwardenBackend {
	b := &vaultwardenBackend{}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			[]*framework.Path{pathConfig(b)},
			pathItems(b),
		),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath},
		},
	}
	return b
}

// getAccessToken returns a valid Vaultwarden access token, re-authenticating if needed.
func (b *vaultwardenBackend) getAccessToken(ctx context.Context, s logical.Storage) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.accessToken != "" && time.Now().Before(b.accessTokenExpiry) {
		return b.accessToken, nil
	}

	cfg, err := getConfig(ctx, s)
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", errNotConfigured
	}

	client := newVaultwardenClient(cfg.URL)
	token, expiresIn, err := client.authenticate(ctx, cfg.ClientID, cfg.ClientSecret)
	if err != nil {
		return "", err
	}

	b.accessToken = token
	b.accessTokenExpiry = time.Now().Add(time.Duration(expiresIn-60) * time.Second)
	return token, nil
}

// getDerivedKeys returns the user's decrypted keys, deriving them on first call.
func (b *vaultwardenBackend) getDerivedKeys(ctx context.Context, s logical.Storage) (*derivedKeys, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.keys != nil {
		return b.keys, nil
	}

	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errNotConfigured
	}

	token, err := b.getAccessTokenLocked(ctx, s, cfg)
	if err != nil {
		return nil, err
	}

	client := newVaultwardenClient(cfg.URL)
	profile, err := client.getProfile(ctx, token)
	if err != nil {
		return nil, err
	}

	masterKey, err := deriveMasterKey(cfg.Email, cfg.MasterPassword,
		profile.Kdf, profile.KdfIterations,
		derefInt(profile.KdfMemory), derefInt(profile.KdfParallelism))
	if err != nil {
		return nil, err
	}

	masterEncKey, masterMacKey, err := stretchMasterKey(masterKey)
	if err != nil {
		return nil, err
	}

	userEncKey, userMacKey, err := decryptUserSymKey(profile.Key, masterEncKey, masterMacKey)
	if err != nil {
		return nil, err
	}

	dk := &derivedKeys{
		userEncKey: userEncKey,
		userMacKey: userMacKey,
		orgKeys:    make(map[string]*symKey),
	}

	if len(profile.Organizations) > 0 && profile.PrivateKey != "" {
		rsaKey, err := decryptRSAPrivateKey(profile.PrivateKey, userEncKey, userMacKey)
		if err == nil {
			dk.rsaKey = rsaKey
			for _, org := range profile.Organizations {
				if org.Key == "" {
					continue
				}
				oEnc, oMac, err := decryptOrgKey(org.Key, rsaKey)
				if err == nil {
					dk.orgKeys[org.ID] = &symKey{encKey: oEnc, macKey: oMac}
				}
			}
		}
	}

	b.keys = dk
	return dk, nil
}

// getAccessTokenLocked is like getAccessToken but assumes b.mu is already held.
func (b *vaultwardenBackend) getAccessTokenLocked(ctx context.Context, s logical.Storage, cfg *vaultwardenConfig) (string, error) {
	if b.accessToken != "" && time.Now().Before(b.accessTokenExpiry) {
		return b.accessToken, nil
	}
	client := newVaultwardenClient(cfg.URL)
	token, expiresIn, err := client.authenticate(ctx, cfg.ClientID, cfg.ClientSecret)
	if err != nil {
		return "", err
	}
	b.accessToken = token
	b.accessTokenExpiry = time.Now().Add(time.Duration(expiresIn-60) * time.Second)
	return token, nil
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

const backendHelp = `
The Vaultwarden secrets engine reads items from a self-hosted Vaultwarden
(Bitwarden-compatible) vault. Configure it with your Vaultwarden URL, API key
(client_id + client_secret), email, and master password. Read from the items/
endpoint to retrieve decrypted vault items by UUID or name.
`
