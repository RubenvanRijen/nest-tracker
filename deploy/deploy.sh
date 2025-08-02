#!/bin/sh
set -e

echo "Pulling latest images..."
docker compose -f docker-compose.yml pull

echo "Starting services..."
docker compose -f docker-compose.yml up -d --remove-orphans

echo "Pruning unused images..."
docker image prune -f

echo "Deployment complete!"
