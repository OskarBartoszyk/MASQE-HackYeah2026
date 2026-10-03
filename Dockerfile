FROM node:22-bookworm-slim AS dashboard
WORKDIR /src/dashboard
COPY dashboard/package*.json ./
RUN npm install
COPY dashboard/ ./
RUN npm run build

FROM golang:1.23-bookworm AS gateway
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY gateway ./gateway
RUN CGO_ENABLED=1 go build -o /out/masqe ./cmd/masqe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=gateway /out/masqe /app/masqe
COPY --from=dashboard /src/dashboard/dist /app/dashboard/dist
COPY policies /app/policies
RUN mkdir -p /app/data
EXPOSE 8080
CMD ["/app/masqe"]
