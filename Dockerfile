FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir -p /app/logs
EXPOSE 3999
CMD ["node", "enhanced-server.js"]
