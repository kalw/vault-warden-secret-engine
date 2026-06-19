FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/vault-vaultwarden-secret-engine ./cmd/vault-vaultwarden-secret-engine

FROM hashicorp/vault:latest
COPY --from=build /out/vault-vaultwarden-secret-engine /vault/plugins/vault-vaultwarden-secret-engine
ENV VAULT_LOCAL_CONFIG='{"plugin_directory":"/vault/plugins"}'
