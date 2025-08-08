# Nest Tracker

A full-stack hour tracking and project management system for teams and freelancers. Built as a monorepo with a modern React frontend and a scalable NestJS backend.

## Features
- User authentication and role-based authorization
- Project management (CRUD, team assignment, status tracking)
- Time tracking (log hours, reporting dashboard)
- Team member profiles and progress tracking
- Visual calendar/timeline for planning
- Personalized dashboard for each user

## Tech Stack
- **Frontend:** React, TypeScript, Tailwind CSS, Vite
- **Backend:** NestJS, TypeScript
- **Database:** PostgreSQL or MongoDB (configurable)
- **Containerization:** Docker, Docker Compose
- **CI/CD:** GitHub Actions

## Installation (Development)

### Prerequisites
- Node.js (v20+)
- Docker & Docker Compose
- Git

### 1. Clone the repository
```sh
git clone https://github.com/yourusername/nest-tracker.git
cd nest-tracker
```

### 2. Install dependencies
```sh
cd backend && npm install
cd ../frontend && npm install
```

### 3. Start in development mode
#### Using Docker Compose (recommended)
```sh
docker-compose up --build
```
- Frontend: http://localhost:5173
- Backend: http://localhost:3000

#### Or run manually
```sh
# In one terminal
cd backend && npm run start:dev
# In another terminal
cd frontend && npm run dev
```

## Production Deployment

1. Build and push Docker images (see `.github/workflows/deploy.yml` for CI/CD)
2. On your server, use the `deploy/` folder:
```sh
cd deploy
./deploy.sh
```
- Frontend will be served on port 80
- Backend will be served on port 3000

## CI/CD
- Automated build, push, and deployment via GitHub Actions
- See `.github/workflows/deploy.yml` for details

## Local Testing (Backend)
This project includes a robust Jest + TypeORM testing setup with isolated Postgres schemas per test file.

Prerequisites:
- Docker running locally
- A Postgres instance (use the repo's docker-compose to start one)

Quick start:
1. Start Postgres locally via Docker Compose:
   ```sh
   docker-compose up -d database
   ```
2. Copy `.env.example` to `.env` and optionally create `.env.testing` to override values only for tests. Example `.env.testing`:
   ```env
   NODE_ENV=test
   DATABASE_URL_TEST=postgresql://nestuser:nestpassword@localhost:5432/nesttracker_test
   JWT_SECRET=local-test-secret-at-least-32-characters-long-123456
   TWOFA_ENCRYPT_KEY=local-twofa-key-at-least-32-characters-long-123456
   TWOFA_ENCRYPT_SALT=local-twofa-salt-16+
   ```
   Note: You do not need to set TEST_SCHEMA; the test harness generates a unique schema per test file.
3. Install backend deps and run tests:
   ```sh
   cd backend
   npm ci
   npm test -- --runInBand
   npm run test:e2e -- --runInBand
   ```

How it works:
- Per-file Jest setup (backend/test/setup-each-test.ts) runs before each test file.
  - Generates a unique Postgres schema (TEST_SCHEMA) for the file.
  - Initializes TypeORM, runs migrations, and seeds baseline data.
  - After the file finishes, it drops the schema and closes the connection.
- This enables clean, isolated DB state and supports parallel test execution.

Seeding:
- The minimal test seed lives at backend/src/seeds/test-seed.ts.
- You can reuse runTestSeed(dataSource) in specific tests if you need to re-seed.

Tips:
- If you see connection errors (ECONNREFUSED), make sure your local Postgres is running and DATABASE_URL_TEST points to it.
- CI runs with a Postgres service and uses the same per-file schema isolation.

## Contributing
Pull requests and issues are welcome! Please follow conventional commit messages and code style.

## License
MIT
