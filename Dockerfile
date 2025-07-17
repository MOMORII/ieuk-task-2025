FROM node:20-alpine

WORKDIR /app

COPY problemfinder.js .
COPY sample-log.log .

CMD ["node", "problemfinder.js"]