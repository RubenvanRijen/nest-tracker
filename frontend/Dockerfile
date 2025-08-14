
FROM node:20-alpine3.20 AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

# --- Development stage ---
FROM base AS development
RUN npm run build
CMD ["npm", "run", "dev"]

FROM nginx:1.27.0-alpine AS production
WORKDIR /usr/share/nginx/html
COPY --from=development /app/dist .
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
