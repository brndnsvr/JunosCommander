.PHONY: help build run test clean docker-build docker-up docker-down db-init traefik-deploy traefik-start traefik-stop traefik-status traefik-logs traefik-cleanup

# Variables
BINARY_NAME=junoscommander
DOCKER_IMAGE=junoscommander:latest
TRAEFIK_COMPOSE_FILE=docker-compose.traefik.yml

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-15s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the Go application
	go build -o bin/$(BINARY_NAME) ./cmd/server

run: ## Run the application locally
	go run ./cmd/server

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	rm -rf bin/
	rm -rf data/*.db
	go clean

docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE) .

docker-up: ## Start Docker services
	docker-compose up -d

docker-down: ## Stop Docker services
	docker-compose down

docker-logs: ## View Docker logs
	docker-compose logs -f

db-init: ## Initialize database
	@echo "Creating database..."
	@mkdir -p data
	@touch data/junoscommander.db
	@echo "Database initialized"

install-deps: ## Install Go dependencies
	go mod download
	go mod tidy

# Traefik Production Deployment Targets
traefik-deploy: ## Deploy JunosCommander with Traefik reverse proxy
	@echo "Deploying JunosCommander with Traefik..."
	./scripts/deploy-traefik.sh deploy

traefik-start: ## Start Traefik deployment
	@echo "Starting Traefik deployment..."
	./scripts/deploy-traefik.sh start

traefik-stop: ## Stop Traefik deployment
	@echo "Stopping Traefik deployment..."
	./scripts/deploy-traefik.sh stop

traefik-restart: ## Restart Traefik deployment
	@echo "Restarting Traefik deployment..."
	./scripts/deploy-traefik.sh restart

traefik-status: ## Show Traefik deployment status
	./scripts/deploy-traefik.sh status

traefik-logs: ## View Traefik logs
	./scripts/deploy-traefik.sh logs

traefik-app-logs: ## View application logs in Traefik deployment
	docker compose -f $(TRAEFIK_COMPOSE_FILE) logs -f junoscommander

traefik-all-logs: ## View all logs in Traefik deployment
	docker compose -f $(TRAEFIK_COMPOSE_FILE) logs -f

traefik-cleanup: ## Clean up Traefik deployment (removes volumes)
	./scripts/deploy-traefik.sh cleanup

traefik-genpass: ## Generate password hash for Traefik dashboard (usage: make traefik-genpass PASS=yourpassword)
	@if [ -z "$(PASS)" ]; then \
		echo "Error: Please provide password with PASS=yourpassword"; \
		exit 1; \
	fi
	./scripts/deploy-traefik.sh genpass $(PASS)

traefik-config: ## Validate Traefik configuration
	docker compose -f $(TRAEFIK_COMPOSE_FILE) config

traefik-pull: ## Pull latest images for Traefik deployment
	docker compose -f $(TRAEFIK_COMPOSE_FILE) pull

traefik-ps: ## Show running containers in Traefik deployment
	docker compose -f $(TRAEFIK_COMPOSE_FILE) ps

# SSL Certificate Management
ssl-test: ## Test SSL configuration with SSL Labs (requires DOMAIN variable)
	@if [ -z "$(DOMAIN)" ]; then \
		echo "Error: Please provide domain with DOMAIN=yourdomain.com"; \
		exit 1; \
	fi
	@echo "Testing SSL configuration for $(DOMAIN)..."
	@echo "Visit: https://www.ssllabs.com/ssltest/analyze.html?d=$(DOMAIN)"

ssl-check: ## Check SSL certificate expiration (requires DOMAIN variable)
	@if [ -z "$(DOMAIN)" ]; then \
		echo "Error: Please provide domain with DOMAIN=yourdomain.com"; \
		exit 1; \
	fi
	@echo "SSL certificate information for $(DOMAIN):"
	@echo | openssl s_client -servername $(DOMAIN) -connect $(DOMAIN):443 2>/dev/null | openssl x509 -noout -dates

# Environment Management
env-template: ## Copy environment template for Traefik
	@if [ -f .env ]; then \
		echo "Warning: .env already exists"; \
		read -p "Overwrite? (y/N): " confirm; \
		if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
			cp .env.traefik .env; \
			echo ".env updated from template"; \
		else \
			echo "Skipping .env update"; \
		fi; \
	else \
		cp .env.traefik .env; \
		echo ".env created from template"; \
		echo "Please edit .env with your configuration"; \
	fi

# Monitoring and Health Checks
health-check: ## Check health of all services
	@echo "Checking service health..."
	@docker compose -f $(TRAEFIK_COMPOSE_FILE) ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}"

monitor: ## Open monitoring dashboards
	@echo "Opening monitoring dashboards..."
	@echo "Traefik Dashboard: https://traefik.example.com/dashboard/"
	@echo "Prometheus: https://prometheus.example.com/"
	@echo "Grafana: https://grafana.example.com/"

# Development with Traefik
dev-with-traefik: ## Start development environment with Traefik
	@echo "Starting development environment with Traefik..."
	@cp .env.traefik .env.dev
	@sed -i.bak 's/production/development/g' .env.dev
	@docker compose -f $(TRAEFIK_COMPOSE_FILE) --env-file .env.dev up -d
	@rm .env.dev.bak

.DEFAULT_GOAL := help