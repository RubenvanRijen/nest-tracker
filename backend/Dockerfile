# --- Build stage ---
FROM node:20-alpine3.20 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci # Install all dependencies, including dev
COPY . .
RUN npm run build

# --- Production stage ---
FROM node:20-alpine3.20 AS production
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./
RUN npm ci --only=production
EXPOSE 3000
CMD ["node", "dist/main.js"]
