#!/bin/bash
set -e

# Make sure REPO_LOWERCASE is set
if [ -z "$REPO_LOWERCASE" ]; then
  echo "Error: REPO_LOWERCASE environment variable is not set"
  exit 1
fi

echo "Pulling latest images..."
docker compose -f docker-compose.yml pull

echo "Stopping and removing old containers..."
docker compose -f docker-compose.yml down --remove-orphans

echo "Starting containers with latest images..."
docker compose -f docker-compose.yml up -d --force-recreate

echo "Cleaning up old images..."
docker image prune -af --filter "until=24h"

echo "Deployment completed successfully!"