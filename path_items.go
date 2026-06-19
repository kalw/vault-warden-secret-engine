package vaultwardensecrets

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func pathItems(b *vaultwardenBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "items/" + framework.GenericNameRegex("id_or_name"),
			Fields: map[string]*framework.FieldSchema{
				"id_or_name": {
					Type:        framework.TypeString,
					Description: "UUID or name of the Vaultwarden item to retrieve.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathItemsRead},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathItemsRead},
			},
			HelpSynopsis:    "Read a Vaultwarden item by UUID or name.",
			HelpDescription: "Returns the decrypted fields of a Vaultwarden vault item. Accepts either a full UUID or a case-insensitive name search.",
		},
		{
			Pattern: "items/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathItemsList},
			},
			HelpSynopsis:    "List Vaultwarden item names.",
			HelpDescription: "Lists the names of all accessible Vaultwarden vault items. Use item UUIDs or names with the items/<id_or_name> path to retrieve credentials.",
		},
	}
}

func (b *vaultwardenBackend) pathItemsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	idOrName := d.Get("id_or_name").(string)

	token, err := b.getAccessToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	keys, err := b.getDerivedKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errNotConfigured
	}
	client := newVaultwardenClient(cfg.URL)

	var item *cipherItem

	if uuidRegex.MatchString(strings.ToLower(idOrName)) {
		item, err = client.getCipher(ctx, token, idOrName)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return logical.ErrorResponse("item %q not found", idOrName), nil
			}
			return nil, err
		}
	} else {
		// Name lookup: fetch all ciphers, decrypt names, find match.
		items, err := client.listCiphers(ctx, token)
		if err != nil {
			return nil, err
		}
		nameLower := strings.ToLower(idOrName)
		for i := range items {
			ci := &items[i]
			orgID := derefStr(ci.OrganizationID)
			enc, mac := keys.keyForCipher(orgID)
			cipherEncKey, cipherMacKey := resolveCipherKey(ci, enc, mac)
			name := decryptStr(&ci.Name, cipherEncKey, cipherMacKey)
			if strings.ToLower(name) == nameLower {
				item = ci
				break
			}
		}
		if item == nil {
			return logical.ErrorResponse("no item found with name %q", idOrName), nil
		}
	}

	data, err := decryptCipher(item, keys)
	if err != nil {
		return nil, fmt.Errorf("decrypt item: %w", err)
	}

	return &logical.Response{Data: data}, nil
}

func (b *vaultwardenBackend) pathItemsList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	token, err := b.getAccessToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	keys, err := b.getDerivedKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errNotConfigured
	}
	client := newVaultwardenClient(cfg.URL)

	items, err := client.listCiphers(ctx, token)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(items))
	for i := range items {
		ci := &items[i]
		// Skip deleted items.
		if ci.DeletedDate != nil {
			continue
		}
		orgID := derefStr(ci.OrganizationID)
		enc, mac := keys.keyForCipher(orgID)
		cipherEncKey, cipherMacKey := resolveCipherKey(ci, enc, mac)
		name := decryptStr(&ci.Name, cipherEncKey, cipherMacKey)
		if name == "" {
			name = ci.ID // fallback for items we couldn't decrypt
		}
		names = append(names, name)
	}

	return logical.ListResponse(names), nil
}

// resolveCipherKey returns the effective enc/mac keys for a cipher.
// If the cipher has its own per-item Key field, it is decrypted first and used instead.
func resolveCipherKey(ci *cipherItem, parentEncKey, parentMacKey []byte) (encKey, macKey []byte) {
	if ci.Key == nil || *ci.Key == "" {
		return parentEncKey, parentMacKey
	}
	// Decrypt the per-cipher key with the parent (user or org) key.
	raw, err := decryptEncString(*ci.Key, parentEncKey, parentMacKey)
	if err != nil || len(raw) != 64 {
		return parentEncKey, parentMacKey
	}
	return raw[:32], raw[32:]
}

// decryptCipher returns a Vault response data map with all decrypted fields of a cipher.
func decryptCipher(ci *cipherItem, keys *derivedKeys) (map[string]interface{}, error) {
	orgID := derefStr(ci.OrganizationID)
	parentEncKey, parentMacKey := keys.keyForCipher(orgID)
	encKey, macKey := resolveCipherKey(ci, parentEncKey, parentMacKey)

	name := decryptStr(&ci.Name, encKey, macKey)
	notes := decryptStr(ci.Notes, encKey, macKey)

	// Custom fields: collect into a string map.
	fields := make(map[string]string, len(ci.Fields))
	for _, f := range ci.Fields {
		if f.Type == 3 { // linked field, no stored value
			continue
		}
		k := decryptStr(f.Name, encKey, macKey)
		v := decryptStr(f.Value, encKey, macKey)
		if k != "" {
			fields[k] = v
		}
	}

	data := map[string]interface{}{
		"id":              ci.ID,
		"name":            name,
		"notes":           notes,
		"fields":          fields,
		"organization_id": orgID,
		"folder_id":       derefStr(ci.FolderID),
		"revision_date":   ci.RevisionDate,
		"creation_date":   ci.CreationDate,
	}

	switch ci.Type {
	case 1: // Login
		data["type"] = "login"
		if ci.Login != nil {
			data["username"] = decryptStr(ci.Login.Username, encKey, macKey)
			data["password"] = decryptStr(ci.Login.Password, encKey, macKey)
			data["totp"] = decryptStr(ci.Login.Totp, encKey, macKey)
			uris := make([]string, 0, len(ci.Login.Uris))
			for _, u := range ci.Login.Uris {
				if u.URI != "" {
					uri := decryptStr(&u.URI, encKey, macKey)
					if uri != "" {
						uris = append(uris, uri)
					}
				}
			}
			data["uris"] = uris
		}

	case 2: // SecureNote
		data["type"] = "secure_note"

	case 3: // Card
		data["type"] = "card"
		if ci.Card != nil {
			data["cardholder_name"] = decryptStr(ci.Card.CardholderName, encKey, macKey)
			data["brand"] = decryptStr(ci.Card.Brand, encKey, macKey)
			data["number"] = decryptStr(ci.Card.Number, encKey, macKey)
			data["exp_month"] = decryptStr(ci.Card.ExpMonth, encKey, macKey)
			data["exp_year"] = decryptStr(ci.Card.ExpYear, encKey, macKey)
			data["code"] = decryptStr(ci.Card.Code, encKey, macKey)
		}

	case 4: // Identity
		data["type"] = "identity"
		if ci.Identity != nil {
			id := ci.Identity
			data["title"] = decryptStr(id.Title, encKey, macKey)
			data["first_name"] = decryptStr(id.FirstName, encKey, macKey)
			data["middle_name"] = decryptStr(id.MiddleName, encKey, macKey)
			data["last_name"] = decryptStr(id.LastName, encKey, macKey)
			data["address1"] = decryptStr(id.Address1, encKey, macKey)
			data["address2"] = decryptStr(id.Address2, encKey, macKey)
			data["address3"] = decryptStr(id.Address3, encKey, macKey)
			data["city"] = decryptStr(id.City, encKey, macKey)
			data["state"] = decryptStr(id.State, encKey, macKey)
			data["postal_code"] = decryptStr(id.PostalCode, encKey, macKey)
			data["country"] = decryptStr(id.Country, encKey, macKey)
			data["company"] = decryptStr(id.Company, encKey, macKey)
			data["email"] = decryptStr(id.Email, encKey, macKey)
			data["phone"] = decryptStr(id.Phone, encKey, macKey)
			data["ssn"] = decryptStr(id.SSN, encKey, macKey)
			data["username"] = decryptStr(id.Username, encKey, macKey)
			data["passport_number"] = decryptStr(id.PassportNumber, encKey, macKey)
			data["license_number"] = decryptStr(id.LicenseNumber, encKey, macKey)
		}

	default:
		data["type"] = fmt.Sprintf("unknown_%d", ci.Type)
	}

	return data, nil
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
