FROM node:18-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY test-target.js .

EXPOSE 4000

CMD ["node", "test-target.js"]