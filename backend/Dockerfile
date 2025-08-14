# --- Base stage ---
FROM node:20-alpine3.20 AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

# --- Development stage ---
FROM base AS development
RUN npm run build
CMD ["npm", "run", "start:dev"]

# --- Production stage ---
FROM base AS production
RUN npm run build
RUN npm prune --production
EXPOSE 3000
CMD ["node", "dist/main.js"]