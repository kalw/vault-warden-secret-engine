FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/vault-warden-secret-engine ./cmd/vault-warden-secret-engine

FROM hashicorp/vault:latest
COPY --from=build /out/vault-warden-secret-engine /vault/plugins/vault-warden-secret-engine
ENV VAULT_LOCAL_CONFIG='{"plugin_directory":"/vault/plugins"}'
