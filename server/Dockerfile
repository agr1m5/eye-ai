FROM node:20-alpine

WORKDIR /app

# Copy dependency definitions
COPY package.json ./
RUN npm install --omit=dev

# Copy source code
COPY . .

EXPOSE 5000

CMD ["node", "src/index.js"]
