FROM golang:1.10-alpine
ENV sourcesdir ${GOPATH}/src/github.com/rcholic/CognitoREST
COPY . ${sourcesdir}
RUN apk update
RUN apk add git
RUN go get -v github.com/Masterminds/glide && cd ${sourcesdir} && glide install && go install

ENTRYPOINT CognitoREST
EXPOSE 3000

