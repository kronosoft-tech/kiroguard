FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /kiroguard .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /kiroguard /kiroguard
USER nonroot:nonroot
ENTRYPOINT ["/kiroguard"]
