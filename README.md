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

## Contributing
Pull requests and issues are welcome! Please follow conventional commit messages and code style.

## License
MIT
