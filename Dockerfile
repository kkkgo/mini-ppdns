FROM golang:alpine AS check
RUN apk update && apk upgrade && apk add --no-cache curl bash bind-tools
WORKDIR /src
COPY . /src/
RUN rm -f go.mod go.sum
RUN go mod init github.com/kkkgo/mini-ppdns
RUN go get -u ./...
RUN go mod tidy
RUN go test -v ./...
RUN go build -ldflags "-s -w" -trimpath -o /usr/bin/mini-ppdns .
RUN bash /src/test.sh

FROM check
WORKDIR /src
CMD rm -f go.mod go.sum && go mod init github.com/kkkgo/mini-ppdns && go get -u ./... && go mod tidy && gofmt -w .