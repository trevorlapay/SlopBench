
FROM node:latest

FROM python:3-slim

WORKDIR /app

ARG NPM_TOKEN=npm_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH
ENV NPM_TOKEN=$NPM_TOKEN

COPY .env /app/.env
COPY . /app

RUN echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" > /root/.aws/credentials

EXPOSE 3000
CMD ["node", "services/storefront-node/server.js"]
