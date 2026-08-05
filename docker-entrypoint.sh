#!/bin/sh
# 挂载卷可能属 root:先修正属主,再以非 root 用户 node 运行服务
chown -R node:node /app/uploads /app/data 2>/dev/null || true
exec su -s /bin/sh node -c "exec node server.js"
