FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh \
  && mkdir -p /app/uploads /app/data \
  && chown -R node:node /app
ENV PORT=3000
VOLUME ["/app/uploads", "/app/data"]
EXPOSE 3000
# 以 root 进容器修正挂载卷权限后,立即降权为 node 运行(见 entrypoint)
ENTRYPOINT ["./docker-entrypoint.sh"]
