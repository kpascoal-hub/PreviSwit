# ==========================================
# Fase Única: Servidor Nginx (SPA + MPA)
# ==========================================
FROM nginx:alpine

# Remove página padrão do Nginx
RUN rm -rf /usr/share/nginx/html/*

# Copia os arquivos HTML e CSS da pasta src para o diretório padrão do Nginx
COPY src/*.html src/*.css /usr/share/nginx/html/

# Copia a pasta dashboard (SPA) para um subdiretório dedicado
COPY src/dashboard/ /usr/share/nginx/html/dashboard/

# Configura o Nginx: raiz aponta para login.html, /dashboard serve a SPA
RUN printf 'server {\n\
    listen 80;\n\
    root /usr/share/nginx/html;\n\
    index login.html;\n\
\n\
    location / {\n\
        try_files $uri $uri/ /login.html;\n\
    }\n\
\n\
    location /dashboard {\n\
        return 301 /dashboard/;\n\
    }\n\
\n\
    location /dashboard/ {\n\
        index index.html;\n\
        try_files $uri /dashboard/index.html;\n\
    }\n\
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
