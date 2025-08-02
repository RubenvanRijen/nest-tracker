# Deployment Guide: nest-tracker

This document explains the full deployment flow for the nest-tracker project, including how files are created, secrets are managed, and containers are started.

---

## 1. Overview
- Deployment is fully automated using GitHub Actions and Docker Compose.
- All secrets and environment variables are managed via a `.env` file (never committed to git).
- The deployment process builds, pushes, syncs, and starts containers on your server.

---

## 2. Deployment Flow

### Step 1: Build & Push Docker Images
- On every push to `main` or `master`, GitHub Actions builds backend and frontend Docker images.
- Images are tagged and pushed to GitHub Container Registry (`ghcr.io`).

### Step 2: Prepare Deployment Files
- The pipeline creates a temporary deployment folder (`temp_deploy`).
- All files from `deploy/` are copied into `temp_deploy`.
- The `.env` file is created from the GitHub secret (`ENV_FILE`) and placed in `temp_deploy`.
- The backend, frontend, and database images are referenced in `docker-compose.yml`.

### Step 3: Sync Files to Server
- The pipeline uses `rsync` (via `ssh-deploy` action) to copy `temp_deploy` to the target server path (`SERVER_DEPLOY_PATH`).
- All deployment files, including `.env`, `docker-compose.yml`, and `deploy.sh`, are now on the server.

### Step 4: Run Deployment Script
- The pipeline connects to the server via SSH and runs `deploy.sh`.
- `deploy.sh` pulls the latest images, stops old containers, starts new ones, and prunes unused images.
- Docker Compose uses the `.env` file to inject all environment variables into the containers.

---

## 3. Environment Variables
- All environment variables (database, ports, secrets) are managed in the `.env` file.
- The `.env` file is created from a GitHub secret and is never committed to git.
- Each service in `docker-compose.yml` uses `env_file: .env` to load variables.

---

## 4. File Locations
- `deploy/` — Contains deployment scripts and configuration.
- `.env` — Created by the pipeline, placed in the deployment folder on the server.
- `docker-compose.yml` — Defines all services (backend, frontend, db) and uses the `.env` file.
- `deploy.sh` — The main deployment script, run on the server.

---

## 5. Flow Summary
1. Developer pushes code to GitHub.
2. GitHub Actions builds and pushes Docker images.
3. Pipeline prepares deployment files and secrets.
4. Files are synced to the server.
5. `deploy.sh` is executed, starting the new containers.
6. The app is live with the latest code and configuration.

---

## 6. Security Notes
- Secrets are managed only in GitHub and injected at deploy time.
- `.env` is never committed to git.
- All SSH keys and server credentials are managed as GitHub secrets.

---

## 7. Troubleshooting
- If deployment fails, check the GitHub Actions logs for errors.
- Ensure the `.env` file is correctly set as a secret in GitHub.
- Make sure the server has Docker and Docker Compose installed.
- Check that all ports and credentials in `.env` match your server setup.

---

## 8. Customization
- To add more services, update `docker-compose.yml` and `.env`.
- To rotate secrets, update the GitHub secret and redeploy.
- To run migrations, add a step to `deploy.sh` or the pipeline.

---

**For questions or improvements, see the main README or open an issue!**
