# =============================================================================
# Dockerfile — previswit-frontend
# Estratégia: Multi-stage build (Node -> Nginx) para React/Vite SPA
# =============================================================================

# Estágio 1: Build (Node)
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json ./
# Ignorando package-lock se não existir, usa npm install
RUN npm install
COPY . .
RUN npm run build

# Estágio 2: Serve (Nginx)
FROM nginx:1.27-alpine

LABEL maintainer="PreviSwit Team" \
      description="PreviSwit Frontend — React SPA (Cyber Dark)" \
      version="4.2"

RUN rm -rf /usr/share/nginx/html/* \
    && rm -f /etc/nginx/conf.d/default.conf

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
