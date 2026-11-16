FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /xroad-diagnostics-exporter .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /xroad-diagnostics-exporter /xroad-diagnostics-exporter
EXPOSE 9792
ENTRYPOINT ["/xroad-diagnostics-exporter"]
