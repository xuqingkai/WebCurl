############################################
# WebCurl
############################################
FROM golang:1.24.4-alpine3.22 AS build-env
WORKDIR /mnt
COPY index.html favicon.ico main.go go.mod  go.sum /mnt/
RUN echo 'start build'
RUN cd /mnt/ && export GO111MODULE=on && export GOPROXY=https://goproxy.cn && CGO_ENABLED=0 go build -o WebCurl

FROM alpine:3.22
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \    
	&& apk update \    
	&& apk add --no-cache tzdata \
	&& cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
	&& mkdir -p /usr/local/WebCurl
COPY --from=build-env /mnt/WebCurl /usr/local/WebCurl
WORKDIR /usr/local/WebCurl
EXPOSE 4444
CMD [ "/usr/local/WebCurl/WebCurl" ]
############################################

# build
# docker build -t webcurl:2.2 .

# start
# docker run -d -p:4444:4444 --name webcurl  webcurl:2.2
# docker run -d --name webcurl -p 4444:4444 -v /usr/share/nginx/html/:/usr/local/WebCurl/webroot webcurl:2.2 /usr/local/WebCurl/WebCurl --webroot=/usr/local/WebCurl/webroot
