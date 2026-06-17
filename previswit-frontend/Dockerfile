# =============================================================================
# Dockerfile — previswit-frontend
# Estratégia: MPA (Multi-Page App) HTML/CSS servida diretamente por Nginx
# Sem build step — Tailwind CSS via CDN + index.css customizado
# =============================================================================
FROM nginx:1.27-alpine

LABEL maintainer="PreviSwit Team" \
      description="PreviSwit Frontend — MPA Nginx (Cyber Dark)" \
      version="4.1"

# Remove configuração e conteúdo padrão do Nginx
RUN rm -rf /usr/share/nginx/html/* \
    && rm -f /etc/nginx/conf.d/default.conf

# ── Estrutura do servidor:
#   /usr/share/nginx/html/
#   ├── index.css           ← Estilos globais (.glass-panel, etc.)
#   ├── login/              ← Tela de login
#   │   ├── index.html
#   │   ├── forgot-password.html
#   │   └── reset-password.html
#   └── dashboard/          ← SPA Vanilla JS (todas as views)
#       ├── index.html      ← Ponto de entrada principal (spa_backup)
#       ├── analytics.html
#       ├── compliance.html
#       ├── pipelines.html
#       └── reports.html
# ────────────────────────────────────────────────────────────────────────────

# Copia o CSS global na raiz (para que ../index.css resolva corretamente)
COPY src/index.css /usr/share/nginx/html/index.css

# Copia a pasta login completa
COPY src/login/ /usr/share/nginx/html/login/

# Copia a pasta dashboard completa
COPY src/dashboard/ /usr/share/nginx/html/dashboard/

# Copia o nginx.conf dedicado
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
