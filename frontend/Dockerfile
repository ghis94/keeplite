# Build stage
FROM node:22-alpine AS builder
WORKDIR /app

COPY package*.json ./
# Need devDependencies (vite) for build
RUN npm ci --include=dev && npm cache clean --force

COPY . .
RUN npm run build

# Runtime stage
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app

# Minimal static file server
RUN npm i -g serve@14 && npm cache clean --force

COPY --from=builder /app/dist ./dist
RUN chown -R node:node /app

USER node
EXPOSE 5173

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:5173').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["serve", "-s", "dist", "-l", "5173"]
