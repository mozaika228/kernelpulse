FROM golang:1.22-bookworm AS build
WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/kernelpulse ./cmd/kernelpulse

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/kernelpulse /kernelpulse
ENTRYPOINT ["/kernelpulse"]
