#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

clear
echo -e "${CYAN}"
cat << "EOF"
   ____                           __       
  / ___| ___  _   _ ___  ___ _ __|  _|_   _ 
 | |  _ / _ \| | | / __|/ _ \ '__| |_| | | |
 | |_| | (_) | |_| \__ \  __/ |  |  _| |_| |
  \____|\___/ \__,_|___/\___|_|  |_|  \__, |
                                      |___/ 
EOF
echo -e "${NC}"
echo -e "${BOLD}User Management Backend - Setup Wizard${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${DIM}Press ENTER to use default value (shown in yellow).${NC}"
echo ""

prompt() {
    local var_name=$1
    local prompt_text=$2
    local default_value=$3
    local is_secret=$4

    if [ "$is_secret" = "true" ]; then
        echo -ne "${BLUE}▸ $prompt_text${NC} ${DIM}(ENTER = auto-generate)${NC}: "
        read -s value
        echo ""
    else
        echo -ne "${BLUE}▸ $prompt_text${NC} [${YELLOW}$default_value${NC}]: "
        read value
    fi
    
    if [ -z "$value" ]; then
        value="$default_value"
        if [ "$is_secret" != "true" ] && [ -n "$default_value" ]; then
            echo -e "  ${DIM}→ Using: $value${NC}"
        fi
    fi
    
    eval "$var_name='$value'"
}

prompt_bool() {
    local var_name=$1
    local prompt_text=$2
    local default_value=$3
    
    local default_display="y/N"
    local hint="no"
    if [ "$default_value" = "true" ]; then
        default_display="Y/n"
        hint="yes"
    fi
    
    echo -ne "${BLUE}▸ $prompt_text${NC} [${YELLOW}$default_display${NC}]: "
    read value
    
    value=$(echo "$value" | tr '[:upper:]' '[:lower:]')
    
    if [ -z "$value" ]; then
        eval "$var_name='$default_value'"
        echo -e "  ${DIM}→ Using: $hint${NC}"
    elif [ "$value" = "y" ] || [ "$value" = "yes" ]; then
        eval "$var_name='true'"
    else
        eval "$var_name='false'"
    fi
}

generate_secret() {
    openssl rand -base64 32 | tr -d '\n'
}

echo -e "${GREEN}▸ Server Configuration${NC}"
echo ""
prompt SERVER_HOST "Server host" "0.0.0.0"
prompt SERVER_PORT "Server port" "8080"
prompt BASE_URL "Base URL" "http://localhost:8080"
prompt ENVIRONMENT "Environment (development/staging/production)" "development"
prompt CORS_ORIGINS "CORS origins (comma-separated)" "http://localhost:3000"

echo ""
echo -e "${GREEN}▸ Database Configuration${NC}"
echo ""
prompt_bool USE_DOCKER "Start PostgreSQL with Docker?" "true"

if [ "$USE_DOCKER" = "true" ]; then
    prompt DOCKER_CONTAINER_NAME "Docker container name" "gouserfy-postgres"
    prompt DB_PORT "Database port" "5432"
    prompt DB_USER "Database user" "gouserfy"
    prompt DB_PASSWORD "Database password" "" true
    if [ -z "$DB_PASSWORD" ]; then
        DB_PASSWORD=$(generate_secret | cut -c1-16)
        echo -e "  ${GREEN}✓${NC} Auto-generated password"
    fi
    prompt DB_NAME "Database name" "gouserfy"
    DB_HOST="localhost"
else
    prompt DB_HOST "Database host" "localhost"
    prompt DB_PORT "Database port" "5432"
    prompt DB_USER "Database user" "gouserfy"
    prompt DB_PASSWORD "Database password" "" true
    prompt DB_NAME "Database name" "gouserfy"
fi
prompt DB_SSLMODE "SSL mode (disable/require/verify-full)" "disable"

echo ""
echo -e "${GREEN}▸ Authentication Configuration${NC}"
echo ""
prompt JWT_SECRET "JWT secret" "" true
if [ -z "$JWT_SECRET" ]; then
    JWT_SECRET=$(generate_secret)
    echo -e "  ${GREEN}✓${NC} Auto-generated JWT secret"
fi
prompt JWT_EXPIRY "JWT expiry" "15m"
prompt REFRESH_TOKEN_EXPIRY "Refresh token expiry" "168h"

echo ""
echo -e "${GREEN}▸ OAuth Configuration${NC}"
echo ""
prompt_bool OAUTH_ENABLED "Enable OAuth?" "false"

if [ "$OAUTH_ENABLED" = "true" ]; then
    echo ""
    prompt_bool OAUTH_GOOGLE_ENABLED "Enable Google OAuth?" "false"
    if [ "$OAUTH_GOOGLE_ENABLED" = "true" ]; then
        prompt OAUTH_GOOGLE_CLIENT_ID "Google Client ID" ""
        prompt OAUTH_GOOGLE_CLIENT_SECRET "Google Client Secret" "" true
        prompt OAUTH_GOOGLE_REDIRECT_URL "Google Redirect URL" "$BASE_URL/api/v1/auth/oauth/google/callback"
    fi

    echo ""
    prompt_bool OAUTH_GITHUB_ENABLED "Enable GitHub OAuth?" "false"
    if [ "$OAUTH_GITHUB_ENABLED" = "true" ]; then
        prompt OAUTH_GITHUB_CLIENT_ID "GitHub Client ID" ""
        prompt OAUTH_GITHUB_CLIENT_SECRET "GitHub Client Secret" "" true
        prompt OAUTH_GITHUB_REDIRECT_URL "GitHub Redirect URL" "$BASE_URL/api/v1/auth/oauth/github/callback"
    fi
fi

echo ""
echo -e "${GREEN}▸ Security Configuration${NC}"
echo ""
prompt RATE_LIMIT_REQUESTS "Rate limit (requests per minute)" "100"
prompt MAX_LOGIN_ATTEMPTS "Max login attempts before lockout" "5"
prompt LOCKOUT_DURATION "Lockout duration" "15m"

echo ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}Generating configuration files...${NC}"
echo ""

cat > .env << EOF
# Server
SERVER_HOST=$SERVER_HOST
SERVER_PORT=$SERVER_PORT
BASE_URL=$BASE_URL
ENVIRONMENT=$ENVIRONMENT
CORS_ORIGINS=$CORS_ORIGINS

# Database
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME
DB_SSLMODE=$DB_SSLMODE
DB_MAX_CONNS=25

# Authentication
JWT_SECRET=$JWT_SECRET
JWT_EXPIRY=$JWT_EXPIRY
REFRESH_TOKEN_EXPIRY=$REFRESH_TOKEN_EXPIRY
PASSWORD_RESET_EXPIRY=1h
EMAIL_VERIFY_EXPIRY=24h

# OAuth
OAUTH_ENABLED=$OAUTH_ENABLED
EOF

if [ "$OAUTH_ENABLED" = "true" ]; then
    cat >> .env << EOF
OAUTH_GOOGLE_ENABLED=${OAUTH_GOOGLE_ENABLED:-false}
OAUTH_GOOGLE_CLIENT_ID=${OAUTH_GOOGLE_CLIENT_ID:-}
OAUTH_GOOGLE_CLIENT_SECRET=${OAUTH_GOOGLE_CLIENT_SECRET:-}
OAUTH_GOOGLE_REDIRECT_URL=${OAUTH_GOOGLE_REDIRECT_URL:-}
OAUTH_GITHUB_ENABLED=${OAUTH_GITHUB_ENABLED:-false}
OAUTH_GITHUB_CLIENT_ID=${OAUTH_GITHUB_CLIENT_ID:-}
OAUTH_GITHUB_CLIENT_SECRET=${OAUTH_GITHUB_CLIENT_SECRET:-}
OAUTH_GITHUB_REDIRECT_URL=${OAUTH_GITHUB_REDIRECT_URL:-}
OAUTH_FACEBOOK_ENABLED=false
EOF
fi

cat >> .env << EOF

# Security
RATE_LIMIT_REQUESTS=$RATE_LIMIT_REQUESTS
RATE_LIMIT_WINDOW=1m
MAX_LOGIN_ATTEMPTS=$MAX_LOGIN_ATTEMPTS
LOCKOUT_DURATION=$LOCKOUT_DURATION
ARGON2_MEMORY=65536
ARGON2_ITERATIONS=3
ARGON2_PARALLELISM=2
EOF

echo -e "${GREEN}✓${NC} Created .env"

if [ "$USE_DOCKER" = "true" ]; then
    echo -e "${CYAN}Starting PostgreSQL with Docker...${NC}"
    
    if docker ps -a --format '{{.Names}}' | grep -q "^${DOCKER_CONTAINER_NAME}$"; then
        echo -e "${YELLOW}Container $DOCKER_CONTAINER_NAME already exists, starting...${NC}"
        docker start "$DOCKER_CONTAINER_NAME" 2>/dev/null || true
    else
        docker run -d \
            --name "$DOCKER_CONTAINER_NAME" \
            -e POSTGRES_USER="$DB_USER" \
            -e POSTGRES_PASSWORD="$DB_PASSWORD" \
            -e POSTGRES_DB="$DB_NAME" \
            -p "$DB_PORT:5432" \
            -v "${DOCKER_CONTAINER_NAME}-data:/var/lib/postgresql/data" \
            postgres:18-alpine
    fi
    
    echo -e "${CYAN}Waiting for PostgreSQL to be ready...${NC}"
    for i in {1..30}; do
        if docker exec "$DOCKER_CONTAINER_NAME" pg_isready -U "$DB_USER" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} PostgreSQL is ready"
            break
        fi
        sleep 1
    done
fi

echo ""
echo -e "${CYAN}Installing Go dependencies...${NC}"
go mod tidy
echo -e "${GREEN}✓${NC} Dependencies installed"

echo ""
echo -e "${CYAN}Running migrations...${NC}"
if command -v goose &> /dev/null; then
    export GOOSE_DRIVER=postgres
    export GOOSE_DBSTRING="postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=$DB_SSLMODE"
    goose -dir migrations up
    echo -e "${GREEN}✓${NC} Migrations completed"
else
    echo -e "${YELLOW}!${NC} Goose not installed. Install with: go install github.com/pressly/goose/v3/cmd/goose@latest"
    echo -e "${YELLOW}!${NC} Then run: goose -dir migrations postgres \"postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=$DB_SSLMODE\" up"
fi

echo ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}${BOLD}Setup complete!${NC}"
echo ""
echo -e "To start the server:"
echo -e "  ${CYAN}go run cmd/gouserfy/main.go${NC}"
echo ""
echo -e "Or build and run:"
echo -e "  ${CYAN}go build -o gouserfy cmd/gouserfy/main.go${NC}"
echo -e "  ${CYAN}./gouserfy${NC}"
echo ""
echo -e "API will be available at: ${BLUE}$BASE_URL/api/v1${NC}"
echo -e "Health check: ${BLUE}$BASE_URL/health${NC}"
echo ""
