#!/bin/bash

# 检查是否有参数传入
if [ $# -eq 0 ]; then
  go build -o WebCurl main.go
  exit 0
fi

# 获取第一个参数
argument="$1"

# 根据第一个参数进行判断
case "$argument" in
  "all")
    rm -rf build
    mkdir -p build
    mkdir -p build/linux
    mkdir -p build/linux/x86
    mkdir -p build/linux/arm64
    mkdir -p build/linux/arm
    mkdir -p build/mac
    mkdir -p build/mac/x86
    mkdir -p build/mac/arm64
    mkdir -p build/windows
    mkdir -p build/windows/x86
    mkdir -p build/windows/arm64
    # linux
    echo 'build linux x86'
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o WebCurl main.go
    mv WebCurl build/linux/x86/WebCurl
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o WebCurl main.go
    echo 'build linux arm64'
    mv WebCurl build/linux/arm64/WebCurl
    CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -o WebCurl main.go
    echo 'build linux arm'
    mv WebCurl build/linux/arm/WebCurl
    # mac
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o WebCurl main.go
    echo 'build mac x86'
    mv WebCurl build/mac/x86/WebCurl
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o WebCurl main.go
    echo 'build mac arm64'
    mv WebCurl build/mac/arm64/WebCurl
    # windows
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o WebCurl.exe main.go
    echo 'build windows x86'
    mv WebCurl.exe build/windows/x86/WebCurl.exe
    CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o WebCurl.exe main.go
    echo 'build windows arm64'
    mv WebCurl.exe build/windows/arm64/WebCurl.exe
    ;;
esac

exit 0
