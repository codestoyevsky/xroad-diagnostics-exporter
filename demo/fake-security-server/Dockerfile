FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY demo/fake-security-server ./demo/fake-security-server
RUN CGO_ENABLED=0 go build -o /fake-security-server ./demo/fake-security-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /fake-security-server /fake-security-server
ENTRYPOINT ["/fake-security-server"]
