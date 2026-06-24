# Local development targets. See the README's "Running locally" section.
.PHONY: run signin db-up db-down test vet build

run: ## Run dauth locally against docker-compose Postgres (generates keys on first run)
	./scripts/run-local.sh

signin: ## Drive the /siwe sign-in flow against a running local dauth
	./scripts/signin.sh

db-up: ## Start the local Postgres
	docker compose up -d --wait db

db-down: ## Stop the local Postgres and delete its data
	docker compose down -v

test: ## Run the Go test suite
	go test ./...

vet:
	go vet ./...

build: ## Build the dauth binary
	go build ./cmd/dauth
