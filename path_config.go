package wardensecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

var errNotConfigured = errors.New("warden backend not configured; write to the config endpoint first")

type wardenConfig struct {
	URL            string `json:"url"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	Email          string `json:"email"`
	MasterPassword string `json:"master_password"`
}

func pathConfig(b *wardenBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:         framework.TypeString,
				Description:  "Base URL of the Warden instance (e.g. https://vault.example.com). No trailing slash.",
				DisplayAttrs: &framework.DisplayAttributes{Name: "Warden URL"},
			},
			"client_id": {
				Type:         framework.TypeString,
				Description:  "API key client ID from Warden account settings (starts with 'user.').",
				DisplayAttrs: &framework.DisplayAttributes{Name: "Client ID", Sensitive: true},
			},
			"client_secret": {
				Type:         framework.TypeString,
				Description:  "API key client secret from Warden account settings.",
				DisplayAttrs: &framework.DisplayAttributes{Name: "Client Secret", Sensitive: true},
			},
			"email": {
				Type:        framework.TypeString,
				Description: "Email address of the Warden account. Used as PBKDF2/Argon2 salt for key derivation.",
			},
			"master_password": {
				Type:         framework.TypeString,
				Description:  "Master password of the Warden account. Used for key derivation to decrypt vault items. Stored sealed in Vault.",
				DisplayAttrs: &framework.DisplayAttributes{Name: "Master Password", Sensitive: true},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    "Configure the Warden secrets engine.",
		HelpDescription: "Set the Warden URL, API key credentials, and master password used to read vault items.",
	}
}

func (b *wardenBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, fmt.Errorf("existence check: %w", err)
	}
	return out != nil, nil
}

func (b *wardenBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"url":             cfg.URL,
			"client_id":       maskSecret(cfg.ClientID),
			"client_secret":   maskSecret(cfg.ClientSecret),
			"email":           cfg.Email,
			"master_password": maskSecret(cfg.MasterPassword),
		},
	}, nil
}

func (b *wardenBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	create := req.Operation == logical.CreateOperation
	if cfg == nil {
		if !create {
			return nil, errors.New("config not found during update")
		}
		cfg = &wardenConfig{}
	}

	if v, ok := d.GetOk("url"); ok {
		cfg.URL = strings.TrimRight(v.(string), "/")
	}
	if v, ok := d.GetOk("client_id"); ok {
		cfg.ClientID = v.(string)
	}
	if v, ok := d.GetOk("client_secret"); ok {
		cfg.ClientSecret = v.(string)
	}
	if v, ok := d.GetOk("email"); ok {
		cfg.Email = v.(string)
	}
	if v, ok := d.GetOk("master_password"); ok {
		cfg.MasterPassword = v.(string)
	}

	if cfg.URL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Email == "" || cfg.MasterPassword == "" {
		return logical.ErrorResponse("all fields are required: url, client_id, client_secret, email, master_password"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Invalidate cached keys and token on config change.
	b.mu.Lock()
	b.accessToken = ""
	b.keys = nil
	b.mu.Unlock()

	return nil, nil
}

func (b *wardenBackend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	b.accessToken = ""
	b.keys = nil
	b.mu.Unlock()
	return nil, req.Storage.Delete(ctx, configStoragePath)
}

func getConfig(ctx context.Context, s logical.Storage) (*wardenConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var cfg wardenConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return &cfg, nil
}

func maskSecret(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}
