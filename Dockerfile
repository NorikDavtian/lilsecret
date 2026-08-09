FROM node:26-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=8080 DATA_DIR=/data
COPY package.json server.js ./
COPY public ./public
EXPOSE 8080
USER node
CMD ["node", "server.js"]
