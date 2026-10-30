FROM node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c AS web
WORKDIR /build
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build
FROM python:3.14.6-slim-bookworm@sha256:4c92ffcde4dd6f1ff72a24518f49fd4990b27134987dfa31a733badde66df9f8
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOST=0.0.0.0
WORKDIR /app
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock && groupadd -g 10001 app && useradd -u 10001 -g app app
COPY app/ app/
COPY samples/ samples/
COPY web/ web/
COPY --from=web /build/web/app.js web/app.js
RUN mkdir artifacts && chown 10001:10001 artifacts
USER 10001:10001
EXPOSE 8080
CMD ["python","-m","app.cli","serve","--demo"]
