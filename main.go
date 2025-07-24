package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"math/rand"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

// Header 定义HTTP请求头结构体，用于JSON序列化和反序列化
type Header struct {
	Name  string `json:"name"`  // 请求头名称
	Value string `json:"value"` // 请求头值
}

// FileInfo 定义文件信息结构体，用于文件上传功能
type FileInfo struct {
	FieldName string `json:"field_name"` // 表单字段名
	FileName  string `json:"file_name"`  // 文件名
}

// ForwardParams 定义转发参数结构体，用于存储WebSocket和SSE连接的参数
type ForwardParams struct {
	URL            string // 目标URL地址
	Headers        string // 请求头JSON字符串
	VerifySSL      string // SSL验证选项 (Y/N)
	FollowRedirect string // 重定向跟随选项 (Y/N)
	Timeout        int    // 超时时间（秒）
	RetryCount     int    // 重试次数
	RetryDelay     int    // 重试延迟（秒）
}

// wsConnParams 存储WebSocket连接的参数映射表
// 键为connect_id，值为ForwardParams
var wsConnParams sync.Map

// sseConnParams 存储SSE连接的参数映射表
// 键为connect_id，值为ForwardParams
var sseConnParams sync.Map

// DetachedProcess Windows系统进程标志，用于后台运行
var DetachedProcess uint32 = 0

// CreateNewProcessGroup Windows系统进程组标志，用于后台运行
var CreateNewProcessGroup uint32 = 0

// controlParams 定义控制参数白名单，用于过滤不需要转发的参数
// 这些参数是WebCurl内部使用的，不应该转发到目标服务器
var controlParams = map[string]bool{
	"url":             true, // 目标URL
	"time_out":        true, // 超时时间
	"retry_count":     true, // 重试次数
	"retry_delay":     true, // 重试延迟
	"method":          true, // 请求方法
	"body_type":       true, // 请求体类型
	"headers":         true, // 请求头
	"body":            true, // 请求体
	"file_info":       true, // 文件信息
	"files":           true, // 文件数据
	"follow_redirect": true, // 重定向跟随
	"verify_ssl":      true, // SSL验证
}

// webroot 静态文件根目录路径，为空时使用内嵌的index.html
var webroot = ""

// form-data上传文件目录
var uploadDir = ""

// embeddedFS 内嵌的前端文件系统，包含index.html和favicon.ico
//
//go:embed index.html tool.html favicon.ico README.md
var embeddedFS embed.FS

// logger 全局日志记录器
var logger *slog.Logger

// server 全局HTTP服务器实例，用于优雅退出
var server *http.Server

// shutdownWg 等待组，用于等待所有goroutine完成
var shutdownWg sync.WaitGroup

// ParseMultipartForm 16G
var maxMemory int64 = 16 << 30

// genConnectID 生成32位随机连接ID
// 用于WebSocket和SSE连接的唯一标识
func genConnectID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 32
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

/*
字段	含义	示例
/C	国家	CN
/ST	省/州	Guangdong
/L	城市	Shenzhen
/O	组织	MyCompany
/OU	部门	Tech
/CN	域名或名称	*.test.com
*/
// parseCertInfo 解析 --cert-info 参数，格式如 "/C=CN/ST=Shanghai/L=Pudong/O=Test/OU=Ops/CN=app.example.net"
func parseCertInfo(certInfo string) pkix.Name {
	name := pkix.Name{}
	if certInfo == "" {
		return name
	}
	fields := strings.Split(certInfo, "/")
	for _, field := range fields {
		if field == "" {
			continue
		}
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := kv[0], kv[1]
		switch key {
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "CN":
			name.CommonName = value
		}
	}
	return name
}

// generateSSLCertificateToDir 生成自签名SSL证书到指定目录，支持自定义主题
// subject: 证书主题信息（可为空，使用默认）
func generateSSLCertificateToDir(dir string, subject pkix.Name) error {
	// 生成2048位RSA私钥
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %v", err)
	}

	// 创建证书模板，设置有效期和基本信息
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10年有效期

	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if subject.CommonName != "" {
		template.DNSNames = append(template.DNSNames, subject.CommonName)
	}

	// 确保目标目录存在
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 设置证书和私钥文件路径
	keyPath := filepath.Join(dir, "ssl_cert.key")
	certPath := filepath.Join(dir, "ssl_cert.pem")

	// 将私钥编码为PEM格式并保存到文件
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(privateKeyPEM), 0600); err != nil {
		return fmt.Errorf("保存私钥失败: %v", err)
	}

	// 创建X.509证书
	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("创建证书失败: %v", err)
	}

	// 将证书编码为PEM格式并保存到文件
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(certPEM), 0644); err != nil {
		return fmt.Errorf("保存证书失败: %v", err)
	}

	return nil
}

// setupLogger 初始化日志系统
// logLevelStr: 日志级别 (debug/info/warn/error)
// logFilePath: 日志文件路径，为空时使用默认路径
// maxLogSize: 日志文件最大大小（字节）
// stdoutLog: 是否在控制台打印日志，默认true
func setupLogger(logLevelStr, logFilePath string, maxLogSize int64, stdoutLog bool) {
	// 根据字符串设置日志级别
	var lvl = slog.LevelWarn
	switch strings.ToLower(logLevelStr) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	default:
		lvl = slog.LevelError
	}

	// 如果未指定日志文件路径，使用默认路径
	if logFilePath == "" {
		exe, err := os.Executable()
		if err != nil {
			logFilePath = "WebCurl.log"
		} else {
			dir := filepath.Dir(exe)
			logFilePath = filepath.Join(dir, "WebCurl.log")
		}
	}

	// 检查日志文件大小，超过限制则清空文件
	if info, err := os.Stat(logFilePath); err == nil && info.Size() > maxLogSize {
		if f, err := os.OpenFile(logFilePath, os.O_TRUNC|os.O_WRONLY, 0644); err == nil {
			_ = f.Close()
		}
	}

	// 创建日志文件或使用控制台输出
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	var handler slog.Handler
	if err != nil {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
		fmt.Printf("无法打开日志文件: %v,日志输出到控制台\n", err)
	} else {
		if stdoutLog {
			handler = slog.NewTextHandler(io.MultiWriter(logFile, os.Stdout), &slog.HandlerOptions{Level: lvl})
		} else {
			handler = slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: lvl})
		}
	}
	logger = slog.New(handler)
	logger.Info("日志初始化", "level", lvl, "file", logFilePath, "stdout", stdoutLog)
}

// daemonizeIfNeeded 跨平台后台运行功能
// daemon: 是否启用后台运行
func daemonizeIfNeeded(daemon bool) {
	if !daemon {
		return
	}
	// 检查是否已经是子进程
	if os.Getenv("GO_DAEMON_MODE_WEB_CURL") == "1" {
		// 已经是子进程
		return
	}

	// 获取可执行文件路径和参数
	exe, _ := os.Executable()
	args := os.Args[1:]
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), "GO_DAEMON_MODE_WEB_CURL=1")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	// 设置进程属性，实现跨平台后台运行
	attr := &syscall.SysProcAttr{}
	rv := reflect.ValueOf(attr).Elem()

	if runtime.GOOS == "windows" {
		// Windows系统：使用反射设置CreationFlags
		if flags := rv.FieldByName("CreationFlags"); flags.IsValid() && flags.CanSet() {
			flags.SetUint(uint64(CreateNewProcessGroup | DetachedProcess))
		}
	} else {
		// Unix系统：使用反射设置SetSid
		if setsid := rv.FieldByName("Setsid"); setsid.IsValid() && setsid.CanSet() {
			setsid.SetBool(true)
		}
	}
	cmd.SysProcAttr = attr

	// 启动后台进程并退出当前进程
	_ = cmd.Start()
	fmt.Println("已切换到后台运行,PID:", cmd.Process.Pid)
	os.Exit(0)
}

// printAndLogConfig 打印并记录服务启动配置信息
func printAndLogConfig(host, port, webroot string, daemon, echoServer bool, logLevel, logFile, logSize, sslCert, sslCertKey, uploadDir string, stdoutLog bool) {
	// 获取默认日志文件路径
	defaultLogFile := "WebCurl.log"
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		defaultLogFile = filepath.Join(dir, "WebCurl.log")
	}

	// 构建配置映射表
	config := map[string]any{
		"--host":         host,
		"--port":         port,
		"--webroot":      webroot,
		"--daemon":       daemon,
		"--echo-server":  echoServer,
		"--log-level":    logLevel,
		"--log-file":     logFile,
		"--log-size":     logSize,
		"--ssl-cert":     sslCert,
		"--ssl-cert-key": sslCertKey,
		"--upload-dir":   uploadDir,
		"--stdout-log":   stdoutLog,
	}

	// 打印配置信息到控制台
	fmt.Println("服务启动配置：")
	for k, v := range config {
		// 对于空字符串，显示默认值
		if str, ok := v.(string); ok && str == "" {
			if k == "--log-file" {
				fmt.Printf("  %-25s: %s (默认)\n", k, defaultLogFile)
			} else if k == "--webroot" {
				fmt.Printf("  %-25s: 使用内嵌index.html (默认)\n", k)
			} else if k == "--ssl-cert" {
				fmt.Printf("  %-25s: ssl_cert.pem (默认)\n", k)
			} else if k == "--ssl-cert-key" {
				fmt.Printf("  %-25s: ssl_cert.key (默认)\n", k)
			} else if k == "--upload-dir" {
				fmt.Printf("  %-25s: <空> (仅透传)\n", k)
			} else {
				fmt.Printf("  %-25s: <空>\n", k)
			}
		} else {
			fmt.Printf("  %-25s: %v\n", k, v)
		}
	}

	// 记录配置信息到日志
	logger.Info("服务启动配置", "config", config)
}

// handleRoot 处理根路径请求，提供静态文件服务
// 优先使用webroot目录，如果为空则使用内嵌的index.html
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if webroot != "" {
		// 优先使用webroot目录
		path := filepath.Join(webroot, r.URL.Path)
		info, err := os.Stat(path)
		if err == nil {
			if info.IsDir() {
				// 如果是目录，尝试查找 index.html
				indexPath := filepath.Join(path, "index.html")
				if _, err := os.Stat(indexPath); err == nil {
					http.ServeFile(w, r, indexPath)
					return
				}
				// 如果没有 index.html，返回 404
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("404 not found"))
				return
			}
			// 如果是文件，直接提供
			http.ServeFile(w, r, path)
			return
		}
		// 如果文件不存在，返回 404
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 not found"))
		return
	}

	// 如果没有指定 webroot，使用内嵌的 index.html
	if r.URL.Path == "/" {
		data, err := embeddedFS.ReadFile("index.html")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("index.html not found"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	if r.URL.Path == "/tool.html" {
		data, err := embeddedFS.ReadFile("tool.html")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("tool.html not found"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 not found"))
}

// handleMode 处理模式检测请求，返回当前服务模式
func handleMode(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"mode": "proxy"}`))
}

// handleFavicon 处理favicon.ico请求
func handleFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := embeddedFS.ReadFile("favicon.ico")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// 获取真实ip
func getRealIP(r *http.Request) string {
	// 1. 尝试从 X-Forwarded-For 头部获取
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For 可能包含多个 IP 地址，取第一个
		ips := strings.Split(forwarded, ",")
		// 循环遍历IP地址，移除空格并验证是否是有效的IP地址
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// 2. 尝试从 X-Real-IP 头部获取
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}

	// 3. 如果以上两种方法都失败，则使用 RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // 如果解析失败，返回原始 RemoteAddr
	}
	if net.ParseIP(ip) != nil {
		return ip
	}
	return r.RemoteAddr
}

// handleForward 处理HTTP请求转发，支持多种请求体格式和文件上传
func handleForward(w http.ResponseWriter, r *http.Request) {
	// 只允许POST方法
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
		logger.Error("拒绝非POST请求", "method", r.Method, "url", r.URL.String())
		return
	}

	logger.Info("收到请求", "method", r.Method, "url", r.URL.String())
	logger.Debug("请求Header", "header", r.Header)

	// 解析multipart/form-data请求，支持最大16GB
	err := r.ParseMultipartForm(maxMemory)
	if err != nil {
		http.Error(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		logger.Error("解析请求失败", "err", err)
		return
	}

	// 获取并验证目标URL
	forwardURL := r.FormValue("url")
	if forwardURL == "" {
		http.Error(w, "缺少目标URL", http.StatusBadRequest)
		logger.Error("缺少目标URL参数")
		return
	}

	// 如果url是localhosl或127.0.0.1、0.0.0.0则替换为请求来源ip
	// 定义正则表达式
	re := regexp.MustCompile(`^(.*://)?(localhost|127\.0\.0\.1|0\.0\.0\.0)`)
	// 使用正则表达式查找匹配项
	match := re.FindStringSubmatch(forwardURL)

	// 如果找到匹配项，则进行替换
	if len(match) > 0 {
		// 构造替换后的 URL
		forwardURL = re.ReplaceAllString(forwardURL, match[1]+getRealIP(r))
	}

	logger.Info("转发目标URL", "url", forwardURL)
	logger.Debug("Form参数", "form", r.Form)

	// 获取SSL验证参数，默认启用
	verifySSL := r.FormValue("verify_ssl")
	if verifySSL == "" {
		verifySSL = "Y"
	}

	// 获取重定向跟随参数，默认启用
	followRedirect := r.FormValue("follow_redirect")
	if followRedirect == "" {
		followRedirect = "Y"
	}

	// 解析超时时间参数
	timeOut := 0
	if timeoutStr := r.FormValue("time_out"); timeoutStr != "" {
		timeOut, err = strconv.Atoi(timeoutStr)
		if err != nil {
			http.Error(w, "无效的超时时间", http.StatusBadRequest)
			return
		}
	}

	// 解析重试次数参数
	retryCount := 0
	if retryStr := r.FormValue("retry_count"); retryStr != "" {
		retryCount, err = strconv.Atoi(retryStr)
		if err != nil {
			http.Error(w, "无效的重试次数", http.StatusBadRequest)
			return
		}
	}

	// 解析重试延迟参数
	retryDelay := 0
	if delayStr := r.FormValue("retry_delay"); delayStr != "" {
		retryDelay, err = strconv.Atoi(delayStr)
		if err != nil {
			http.Error(w, "无效的重试延迟", http.StatusBadRequest)
			return
		}
	}

	// 获取请求方法，默认为GET
	method := r.FormValue("method")
	if method == "" {
		method = http.MethodGet
	}

	// 获取请求体类型，默认为none
	bodyType := r.FormValue("body_type")
	if bodyType == "" {
		bodyType = "none"
	}

	// 解析请求头JSON
	var headers []Header
	if headersStr := r.FormValue("headers"); headersStr != "" {
		if err := json.Unmarshal([]byte(headersStr), &headers); err != nil {
			http.Error(w, "解析请求头失败: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// 解析文件信息JSON
	var filesInfo []FileInfo
	if filesInfoStr := r.FormValue("file_info"); filesInfoStr != "" {
		if err := json.Unmarshal([]byte(filesInfoStr), &filesInfo); err != nil {
			http.Error(w, "解析文件信息失败: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// 处理WebSocket连接请求
	if method == "WS" {
		params := ForwardParams{
			URL:            forwardURL,
			Headers:        r.FormValue("headers"),
			VerifySSL:      verifySSL,
			FollowRedirect: followRedirect,
			Timeout:        timeOut,
			RetryCount:     retryCount,
			RetryDelay:     retryDelay,
		}
		connectID := genConnectID()
		wsConnParams.Store(connectID, params)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"connect_id":"%s","code":0,"msg":"OK"}`, connectID)))
		return
	}

	// 处理SSE连接请求
	if method == "SSE" {
		params := ForwardParams{
			URL:            forwardURL,
			Headers:        r.FormValue("headers"),
			VerifySSL:      verifySSL,
			FollowRedirect: followRedirect,
			Timeout:        timeOut,
			RetryCount:     retryCount,
			RetryDelay:     retryDelay,
		}
		connectID := genConnectID()
		sseConnParams.Store(connectID, params)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"connect_id":"%s","code":0,"msg":"OK"}`, connectID)))
		return
	}

	// 准备请求体数据
	var requestBodyBytes []byte
	var contentType string

	// 创建文件映射：字段名 -> 文件信息列表
	fieldToFiles := make(map[string][]FileInfo)
	for _, fi := range filesInfo {
		fieldToFiles[fi.FieldName] = append(fieldToFiles[fi.FieldName], fi)
	}

	// 根据请求体类型处理数据
	switch strings.ToLower(bodyType) {
	case "form-data":
		// 处理multipart/form-data格式
		bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(bodyBuf)

		// 添加普通表单字段
		for key, values := range r.MultipartForm.Value {
			if !controlParams[key] {
				for _, value := range values {
					_ = bodyWriter.WriteField(key, value)
				}
			}
		}

		// 处理文件上传
		for fieldName, files := range fieldToFiles {
			for _, fileInfo := range files {
				// 在原始请求中查找匹配的文件
				var foundFile *multipart.FileHeader
				for _, fileHeaders := range r.MultipartForm.File {
					for _, fh := range fileHeaders {
						if fh.Filename == fileInfo.FileName {
							foundFile = fh
							break
						}
					}
					if foundFile != nil {
						break
					}
				}

				if foundFile == nil {
					http.Error(w, "文件未上传: "+fileInfo.FileName, http.StatusBadRequest)
					return
				}

				file, err := foundFile.Open()
				if err != nil {
					http.Error(w, "打开文件失败: "+err.Error(), http.StatusInternalServerError)
					return
				}

				// 使用流式处理避免大文件内存占用
				filePart, err := bodyWriter.CreateFormFile(fieldName, fileInfo.FileName)
				if err != nil {
					_ = file.Close()
					http.Error(w, "创建表单文件失败: "+err.Error(), http.StatusInternalServerError)
					return
				}

				if _, err := io.Copy(filePart, file); err != nil {
					_ = file.Close()
					http.Error(w, "写入文件数据失败: "+err.Error(), http.StatusInternalServerError)
					return
				}
				// 立即关闭文件，避免在循环中累积文件句柄
				_ = file.Close()
			}
		}

		// 完成multipart写入
		if err := bodyWriter.Close(); err != nil {
			http.Error(w, "关闭multipart写入器失败: "+err.Error(), http.StatusInternalServerError)
			return
		}

		contentType = bodyWriter.FormDataContentType()
		requestBodyBytes = bodyBuf.Bytes()

	case "x-www-form-urlencoded":
		// 处理application/x-www-form-urlencoded格式
		data := url.Values{}
		for key, values := range r.MultipartForm.Value {
			if !controlParams[key] {
				for _, value := range values {
					data.Add(key, value)
				}
			}
		}
		contentType = "application/x-www-form-urlencoded"
		requestBodyBytes = []byte(data.Encode())

	case "json":
		// 处理application/json格式
		jsonBody := r.FormValue("body")
		contentType = "application/json"
		requestBodyBytes = []byte(jsonBody)

	case "text":
		// 处理text/plain格式
		textBody := r.FormValue("body")
		contentType = "text/plain"
		requestBodyBytes = []byte(textBody)

	case "xml":
		// 处理application/xml格式
		xmlBody := r.FormValue("body")
		contentType = "application/xml"
		requestBodyBytes = []byte(xmlBody)

	case "binary":
		// 处理二进制文件上传
		if files := r.MultipartForm.File["files"]; len(files) > 0 {
			file, err := files[0].Open()
			if err != nil {
				http.Error(w, "打开文件失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			defer file.Close()

			fileData, err := io.ReadAll(file)
			if err != nil {
				http.Error(w, "读取文件失败: "+err.Error(), http.StatusBadRequest)
				return
			}

			contentType = "application/octet-stream"
			requestBodyBytes = fileData
		}

	case "none", "":
		// 无请求体
		requestBodyBytes = nil

	default:
		http.Error(w, "不支持的请求体类型: "+bodyType, http.StatusBadRequest)
		return
	}

	// 创建目标URL
	targetURL, err := url.Parse(forwardURL)
	if err != nil {
		http.Error(w, "无效的目标URL: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 设置HTTP客户端
	client := &http.Client{}
	if timeOut > 0 {
		client.Timeout = time.Duration(timeOut) * time.Second
	}
	// 如果 verify_ssl == "N",跳过 SSL 验证
	if verifySSL == "N" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	// 如果 follow_redirect == "N",不跟随 3XX 跳转
	if followRedirect == "N" {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// 执行请求重试逻辑
	var resp *http.Response
	for i := 0; i <= retryCount; i++ {
		if i > 0 && retryDelay > 0 {
			time.Sleep(time.Duration(retryDelay) * time.Second)
		}

		// 准备请求体读取器
		var bodyReader io.Reader
		if requestBodyBytes != nil {
			bodyReader = bytes.NewReader(requestBodyBytes)
		} else {
			bodyReader = nil
		}

		// 创建HTTP请求
		httpReq, err := http.NewRequest(method, targetURL.String(), bodyReader)
		if err != nil {
			if i == retryCount {
				http.Error(w, "创建HTTP请求失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			continue
		}

		// 设置请求头
		if contentType != "" {
			httpReq.Header.Set("Content-Type", contentType)
		}

		// 添加用户自定义的请求头
		for _, header := range headers {
			httpReq.Header.Set(header.Name, header.Value)
		}

		// 发送请求
		resp, err = client.Do(httpReq)
		if err == nil && resp.StatusCode < 500 {
			logger.Info("转发成功", "method", method, "target", targetURL.String(), "status", resp.StatusCode)
			logger.Debug("响应Header", "header", resp.Header)
			break
		}

		if err != nil && i == retryCount {
			http.Error(w, "转发请求失败: "+err.Error(), http.StatusInternalServerError)
			logger.Error("转发请求失败", "err", err)
			return
		}

	}

	// 确保resp不为nil
	if resp == nil {
		http.Error(w, "转发请求失败: 没有有效的响应", http.StatusInternalServerError)
		logger.Error("转发请求失败: 没有有效的响应")
		return
	}
	defer resp.Body.Close()

	// 将响应头复制到响应写入器
	// 创建一个映射来存储所有响应头
	responseHeaders := make(map[string][]string)
	for key, values := range resp.Header {
		// 将每个响应头添加到响应中
		for _, value := range values {
			w.Header().Add(key, value)
		}
		// 同时将响应头存储在映射中
		responseHeaders[key] = values
	}

	// 添加一个特殊的响应头来传递所有头信息
	if headersJSON, err := json.Marshal(responseHeaders); err == nil {
		w.Header().Set("X-Response-Headers", string(headersJSON))
	}

	// 设置状态码并复制响应体
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, "复制响应体失败: "+err.Error(), http.StatusInternalServerError)
	}
}

// websocketForward 实现WebSocket双向转发功能
// ws1: 客户端WebSocket连接
// ws2: 目标服务器WebSocket连接
func websocketForward(ws1, ws2 *Conn) {
	// 添加到等待组，确保优雅退出时等待所有连接完成
	shutdownWg.Add(1)
	defer shutdownWg.Done()

	var wg sync.WaitGroup
	wg.Add(2)

	// 定义转发函数，用于双向数据转发
	forward := func(dst, src *Conn, name string) {
		defer wg.Done()
		defer func() { _ = dst.Close(); _ = src.Close() }()

		// 设置无超时
		_ = src.SetReadDeadline(time.Time{})
		_ = dst.SetWriteDeadline(time.Time{})

		// 设置ping/pong处理器
		src.SetPingHandler(func(data string) error {
			return dst.WriteControl(PongMessage, []byte(data), time.Now().Add(10*time.Second))
		})
		src.SetPongHandler(func(string) error { return nil })

		// 持续转发消息
		for {
			messageType, data, err := src.ReadMessage()
			if err != nil {
				return
			}
			if err := dst.WriteMessage(messageType, data); err != nil {
				return
			}
		}
	}

	// 启动两个goroutine进行双向转发
	go forward(ws1, ws2, "ws1<-->ws2")
	go forward(ws2, ws1, "ws2<-->ws1")
	wg.Wait()
}

// handleForwardWS 处理WebSocket转发请求
func handleForwardWS(w http.ResponseWriter, r *http.Request) {
	// 获取连接ID
	connectID := r.URL.Query().Get("connect_id")
	if connectID == "" {
		http.Error(w, "缺少connect_id", http.StatusBadRequest)
		return
	}
	defer wsConnParams.Delete(connectID)

	// 获取连接参数
	v, ok := wsConnParams.Load(connectID)
	if !ok {
		http.Error(w, "无效的connect_id", http.StatusBadRequest)
		return
	}
	params := v.(ForwardParams)

	// 升级HTTP连接为WebSocket连接
	wsUpgrade := Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	clientConn, err := wsUpgrade.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer clientConn.Close()

	// 解析请求头
	headers := http.Header{}
	if params.Headers != "" {
		var hs []Header
		_ = json.Unmarshal([]byte(params.Headers), &hs)
		for _, h := range hs {
			headers.Set(h.Name, h.Value)
		}
	}

	// 配置WebSocket拨号器
	dialer := Dialer{}
	if params.VerifySSL == "N" {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if params.Timeout > 0 {
		dialer.HandshakeTimeout = time.Duration(params.Timeout) * time.Second
	}

	// 重试机制连接目标WebSocket
	var targetConn *Conn
	var resp *http.Response
	var dialErr error
	for i := 0; i <= params.RetryCount; i++ {
		if i > 0 && params.RetryDelay > 0 {
			time.Sleep(time.Duration(params.RetryDelay) * time.Second)
		}
		targetConn, resp, dialErr = dialer.Dial(params.URL, headers)
		if dialErr == nil {
			break
		}
	}

	if dialErr != nil {
		_ = clientConn.WriteMessage(TextMessage, []byte("连接目标WS失败: "+dialErr.Error()))
		_ = clientConn.Close()
		return
	}

	// 发送响应头信息
	if resp != nil {
		defer resp.Body.Close()
		headerMap := map[string][]string{}
		for k, v := range resp.Header {
			headerMap[k] = v
		}
		headerJson, _ := json.Marshal(headerMap)
		_ = clientConn.WriteMessage(TextMessage, []byte(`{"type":"headers","headers":`+string(headerJson)+`}`))
	}
	defer targetConn.Close()

	// 开始双向转发
	websocketForward(clientConn, targetConn)
}

// handleForwardSSE 处理SSE（Server-Sent Events）转发请求
func handleForwardSSE(w http.ResponseWriter, r *http.Request) {
	// 添加到等待组，确保优雅退出时等待所有连接完成
	shutdownWg.Add(1)
	defer shutdownWg.Done()

	// 获取连接ID
	connectID := r.URL.Query().Get("connect_id")
	if connectID == "" {
		http.Error(w, "缺少connect_id", http.StatusBadRequest)
		return
	}
	defer sseConnParams.Delete(connectID)

	// 获取连接参数
	v, ok := sseConnParams.Load(connectID)
	if !ok {
		http.Error(w, "无效的connect_id", http.StatusBadRequest)
		return
	}
	params := v.(ForwardParams)

	// 创建SSE请求
	req, err := http.NewRequest("GET", params.URL, nil)
	if err != nil {
		http.Error(w, "创建SSE请求失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 设置请求头
	if params.Headers != "" {
		var hs []Header
		_ = json.Unmarshal([]byte(params.Headers), &hs)
		for _, h := range hs {
			req.Header.Set(h.Name, h.Value)
		}
	}

	// 配置HTTP客户端
	client := &http.Client{}
	tr := &http.Transport{}
	if params.VerifySSL == "N" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client.Transport = tr
	if params.Timeout > 0 {
		client.Timeout = time.Duration(params.Timeout) * time.Second
	}

	// 配置重定向处理
	if params.FollowRedirect == "N" {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// 重试机制连接目标SSE
	var resp *http.Response
	var sseErr error
	for i := 0; i <= params.RetryCount; i++ {
		if i > 0 && params.RetryDelay > 0 {
			time.Sleep(time.Duration(params.RetryDelay) * time.Second)
		}
		resp, sseErr = client.Do(req)
		if sseErr == nil {
			break
		}
	}

	if sseErr != nil {
		http.Error(w, "连接目标SSE失败: "+sseErr.Error(), http.StatusInternalServerError)
		return
	}

	if resp == nil {
		http.Error(w, "SSE response is null", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 设置SSE响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// 获取响应刷新器
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// 发送响应头信息
	headerMap := map[string][]string{}
	for k, v := range resp.Header {
		headerMap[k] = v
	}
	headerJson, _ := json.Marshal(headerMap)
	_, _ = w.Write([]byte("event: x-web-curl-headers\ndata: " + string(headerJson) + "\n\n"))
	flusher.Flush()

	// 逐行读取并转发SSE消息
	reader := bufio.NewReader(resp.Body)
	var msgLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			// 空行，表示一个完整SSE消息结束
			if len(msgLines) > 0 {
				msg := strings.Join(msgLines, "\n")
				_, _ = w.Write([]byte(msg + "\n\n"))
				flusher.Flush()
				msgLines = msgLines[:0]
			}
		} else {
			msgLines = append(msgLines, line)
		}
		if err != nil {
			break
		}
	}
}

// gracefulShutdown 优雅退出处理函数
// 清理所有连接和资源，确保程序安全退出
func gracefulShutdown(ctx context.Context) {
	logger.Info("开始关闭程序...")

	// 清理WebSocket连接参数
	wsConnParams.Range(func(key, value interface{}) bool {
		logger.Info("清理WebSocket连接参数", "connect_id", key)
		wsConnParams.Delete(key)
		return true
	})

	// 清理SSE连接参数
	sseConnParams.Range(func(key, value interface{}) bool {
		logger.Info("清理SSE连接参数", "connect_id", key)
		sseConnParams.Delete(key)
		return true
	})

	// 等待所有goroutine完成
	logger.Info("等待所有goroutine完成...")
	shutdownWg.Wait()

	// 关闭HTTP服务器
	if server != nil {
		logger.Info("关闭HTTP服务器...")
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("关闭HTTP服务器失败", "err", err)
		} else {
			logger.Info("HTTP服务器已关闭")
		}
	}

	logger.Info("优雅退出完成")
}

// recoverMiddleware 全局panic恢复中间件
// 参考gin框架的recovery实现，提供完善的panic处理机制
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// 检查是否为连接断开错误
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					var se *os.SyscallError
					if errors.As(ne, &se) {
						seStr := strings.ToLower(se.Error())
						if strings.Contains(seStr, "broken pipe") ||
							strings.Contains(seStr, "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				// 记录panic信息
				stack := getStack(3)
				httpRequest, _ := httputil.DumpRequest(r, false)
				headers := strings.Split(string(httpRequest), "\r\n")
				maskAuthorization(headers)
				headersToStr := strings.Join(headers, "\r\n")

				if brokenPipe {
					logger.Error("disconnect_panic", "err", err, "headers", headersToStr)
				} else {
					logger.Error("panic_recover",
						"time", time.Now().Format("2006-01-02T15:04:05"),
						"headers", headersToStr,
						"err", err,
						"stack", string(stack))
				}

				// 如果连接断开，无法写入响应
				if brokenPipe {
					return
				}

				// 防止写入响应头后再次写入
				if w.Header().Get("Content-Length") == "" {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}
		}()
		// 处理 HTTP CONNECT 请求方法
		/*
			协议规范要求 (RFC 7231)：
			CONNECT 请求必须指定 host:port，不能包含路径
			语法：CONNECT host:port HTTP/1.1
			示例：CONNECT example.com:443 HTTP/1.1

			设计本质：
			CONNECT 是建立 TCP 隧道，不是资源访问
			隧道建立后传输的是原始字节流（可能是 TLS/SSL、SSH 等协议）
			路由路径属于应用层概念，与传输层隧道不兼容
		*/
		if r.Method == http.MethodConnect && r.URL.Path == "" {
			logger.Info("HTTP CONNECT PROXY")
			handleConnect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getStack 获取格式化的调用栈信息
func getStack(skip int) []byte {
	buf := new(bytes.Buffer)
	var lines [][]byte
	var lastFile string

	for i := skip; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}

		_, _ = fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
		if file != lastFile {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			lines = bytes.Split(data, []byte{'\n'})
			lastFile = file
		}
		_, _ = fmt.Fprintf(buf, "\t%s: %s\n", getFunctionName(pc), getSourceLine(lines, line))
	}
	return buf.Bytes()
}

// getFunctionName 获取函数名称
func getFunctionName(pc uintptr) string {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "???"
	}
	name := fn.Name()

	// 移除包路径前缀
	if lastSlash := strings.LastIndexByte(name, '/'); lastSlash >= 0 {
		name = name[lastSlash+1:]
	}
	if period := strings.IndexByte(name, '.'); period >= 0 {
		name = name[period+1:]
	}
	name = strings.ReplaceAll(name, "·", ".")
	return name
}

// getSourceLine 获取源代码行
func getSourceLine(lines [][]byte, n int) []byte {
	n-- // 栈跟踪中行号从1开始，但数组从0开始
	if n < 0 || n >= len(lines) {
		return []byte("???")
	}
	return bytes.TrimSpace(lines[n])
}

// maskAuthorization 隐藏敏感的头信息
func maskAuthorization(headers []string) {
	for idx, header := range headers {
		key, _, _ := strings.Cut(header, ":")
		if strings.EqualFold(key, "Authorization") {
			headers[idx] = key + ": *"
		}
	}
}

// handleTestPanic 测试panic恢复的处理器
func handleTestPanic(_ http.ResponseWriter, r *http.Request) {
	// 根据查询参数决定触发不同类型的panic
	panicType := r.URL.Query().Get("type")

	switch panicType {
	case "string":
		panic("测试字符串panic")
	case "error":
		panic(errors.New("测试错误panic"))
	case "nil":
		var s *string
		*s = "触发空指针panic" // 这会触发panic
	case "array":
		arr := []int{1, 2, 3}
		_ = arr[10] // 数组越界panic
	default:
		panic("默认测试panic")
	}
}

// init 初始化函数，设置Windows系统特定的进程标志
func init() {
	if runtime.GOOS == "windows" {
		DetachedProcess = 0x00000008
		CreateNewProcessGroup = 0x00000200
	}
}

// main 主函数，程序入口点
func main() {
	// 定义命令行参数
	host := flag.String("host", "0.0.0.0", "监听地址")
	port := flag.String("port", "4444", "监听端口")
	webrootFlag := flag.String("webroot", "", "静态文件根目录(为空则用内嵌index.html)")
	daemon := flag.Bool("daemon", false, "后台运行(Linux/MacOS/Windows均支持)")
	echoServer := flag.Bool("echo-server", true, "是否开启一个echoServer模拟Web服务器")
	logLevelFlag := flag.String("log-level", "info", "日志级别: error, info, warn, debug")
	logFileFlag := flag.String("log-file", "", "日志文件路径,未指定则在可执行文件同目录 WebCurl.log")
	logSizeFlag := flag.String("log-size", "100M", "日志文件大小限制,支持单位：K|M|G,默认100M")
	sslCertFlag := flag.String("ssl-cert", "ssl_cert.pem", "SSL证书文件路径")
	sslCertKeyFlag := flag.String("ssl-cert-key", "ssl_cert.key", "SSL证书密钥文件路径")
	genCertDir := flag.String("gen-cert", "", "生成SSL证书文件到指定目录（如 --gen-cert ./certs）")
	certInfoFlag := flag.String("cert-info", "", "自定义证书主题信息,如: /C=CN/ST=Beijing/L=ShunYi/O=Test/OU=Ops/CN=app.example.com")
	uploadDirFlag := flag.String("upload-dir", "", "form-data上传文件保存目录(为空不保存,仅透传)")
	stdoutLogFlag := flag.Bool("stdout-log", true, "是否在控制台打印日志，默认true")
	flag.Parse()

	// 如果指定了生成证书，则生成证书后退出
	if *genCertDir != "" {
		dir := *genCertDir
		if dir == "." || dir == "./" {
			dir, _ = os.Getwd()
		}
		subject := parseCertInfo(*certInfoFlag)
		if reflect.DeepEqual(subject, pkix.Name{}) {
			subject = pkix.Name{
				Organization: []string{"WebCurl Self-Signed Certificate"},
				Country:      []string{"CN"},
				Province:     []string{"Unknown"},
				Locality:     []string{"Unknown"},
				CommonName:   "localhost",
			}
		}
		if err := generateSSLCertificateToDir(dir, subject); err != nil {
			fmt.Printf("生成SSL证书失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SSL证书生成成功: %s/ssl_cert.pem, %s/ssl_cert.key\n", dir, dir)
		fmt.Println("证书有效期: 10年")
		os.Exit(0)
	}

	// 设置全局变量
	webroot = *webrootFlag
	uploadDir = *uploadDirFlag

	// 解析日志大小参数,默认100MB
	maxLogSize := int64(100 * 1024 * 1024)
	if *logSizeFlag != "" {
		size := *logSizeFlag
		unit := size[len(size)-1:]
		num, err := strconv.ParseInt(size[:len(size)-1], 10, 64)
		if err == nil {
			switch strings.ToUpper(unit) {
			case "K":
				maxLogSize = num * 1024
			case "M":
				maxLogSize = num * 1024 * 1024
			case "G":
				maxLogSize = num * 1024 * 1024 * 1024
			default:
				// 默认按MB处理
				maxLogSize = num * 1024 * 1024
			}
		}
	}

	// 初始化日志系统
	setupLogger(*logLevelFlag, *logFileFlag, maxLogSize, *stdoutLogFlag)

	// 检查SSL证书配置
	useSSL := false
	sslCert := *sslCertFlag
	sslCertKey := *sslCertKeyFlag

	// 如果用户没有指定证书路径，尝试在当前目录查找默认证书
	if sslCert == "ssl_cert.pem" && sslCertKey == "ssl_cert.key" {
		exe, err := os.Executable()
		if err == nil {
			dir := filepath.Dir(exe)
			defaultCert := filepath.Join(dir, "ssl_cert.pem")
			defaultKey := filepath.Join(dir, "ssl_cert.key")
			if _, err := os.Stat(defaultCert); err == nil {
				if _, err := os.Stat(defaultKey); err == nil {
					sslCert = defaultCert
					sslCertKey = defaultKey
					useSSL = true
				}
			}
		}
	} else {
		// 用户指定了证书路径，检查文件是否存在
		if _, err := os.Stat(sslCert); err == nil {
			if _, err := os.Stat(sslCertKey); err == nil {
				useSSL = true
			}
		}
	}

	// 打印并记录配置信息
	printAndLogConfig(*host, *port, webroot, *daemon, *echoServer, *logLevelFlag, *logFileFlag, *logSizeFlag, sslCert, sslCertKey, uploadDir, *stdoutLogFlag)

	// 跨平台后台运行
	daemonizeIfNeeded(*daemon)

	// 注册HTTP路由处理器
	// 正常模式
	http.HandleFunc("/", handleRoot)                      // 静态文件服务
	http.HandleFunc("/favicon.ico", handleFavicon)        // favicon图标
	http.HandleFunc("/api/forward", handleForward)        // HTTP请求转发
	http.HandleFunc("/api/mode", handleMode)              // 模式检测
	http.HandleFunc("/api/forward-ws", handleForwardWS)   // WebSocket转发
	http.HandleFunc("/api/forward-sse", handleForwardSSE) // SSE转发
	http.HandleFunc("/api/test-panic", handleTestPanic)   // 测试panic恢复

	if *echoServer {
		http.HandleFunc("/api/echo", handleEchoRequest)
		http.HandleFunc("/api/sse/echo", handleSSEEchoRequest)
		http.HandleFunc("/api/ws/echo", handleWebSocketEchoRequest)
		http.HandleFunc("/api/sse/set", handleSSESet)
		http.HandleFunc("/api/ws/set", handleWSSet)
	}

	// 构建监听地址
	addr := fmt.Sprintf("%s:%s", *host, *port)

	// 创建HTTP服务器实例，使用recover中间件包装默认的ServeMux
	server = &http.Server{
		Addr: addr,
		// 使用recover中间件包装
		Handler: recoverMiddleware(http.DefaultServeMux),
	}

	// 设置信号处理，实现优雅退出
	sigChan := make(chan os.Signal, 1)
	// Windows下需要监听更多信号类型
	if runtime.GOOS == "windows" {
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	} else {
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	}

	// 启动服务器协程
	go func() {
		if useSSL {
			fmt.Printf("HTTPS服务启动在 https://%s\n", addr)
			logger.Info("HTTPS服务启动", "addr", addr, "cert", sslCert, "key", sslCertKey)
			if err := server.ListenAndServeTLS(sslCert, sslCertKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("HTTPS服务启动失败", "err", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("HTTP服务启动在 http://%s\n", addr)
			logger.Info("HTTP服务启动", "addr", addr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("HTTP服务启动失败", "err", err)
				os.Exit(1)
			}
		}
	}()

	// 添加调试信息
	fmt.Printf("\n程序启动完成，按 Ctrl+C 退出; OS:[ %s ]; PID:[ %d ];\n\n", runtime.GOOS, os.Getpid())
	logger.Info(fmt.Sprintf("程序启动完成;OS:[ %s ]; PID:[ %d ];\n\n", runtime.GOOS, os.Getpid()))

	sig := <-sigChan
	logger.Warn("收到退出信号", "signal", sig.String(), "os", runtime.GOOS)

	// 创建超时上下文，30秒内完成优雅退出
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 执行优雅退出
	gracefulShutdown(ctx)

	logger.Info("程序退出")
}

//====================================================================================================
//
// Web EchoServer 服务
//
//====================================================================================================

// 全局存储 SSE/WS 队列
var (
	sseUserQueue = struct {
		sync.Mutex
		Items []any
	}{}
	wsUserQueue = struct {
		sync.Mutex
		Items []any
	}{}
)

// WS react模式下的channel
var wsReactCh = make(chan any, 100)

func handleEchoRequest(w http.ResponseWriter, r *http.Request) {
	// 支持 CORS 预检请求
	if r.Method == "OPTIONS" {
		// w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Expose-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Response-Status-Code, X-Response-Status-Text, X-Response-Location, X-Response-Headers, X-Response-Type, X-Response-Sleep, X-Response-Body, X-Response-Download")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 1. 解析自定义响应参数，优先Header
	statusCode := http.StatusOK
	if sc := getParam(r, "X-Response-Status-Code"); sc != "" {
		if code, err := parseStatusCode(sc); err == nil {
			statusCode = code
		}
	}

	if sleep := getParam(r, "X-Response-Sleep"); sleep != "" {
		if duration, err := strconv.Atoi(sleep); err == nil && duration > 0 {
			time.Sleep(time.Duration(duration) * time.Millisecond)
		}
	}

	location := getParam(r, "X-Response-Location")
	respType := strings.ToLower(getParam(r, "X-Response-Type"))
	customHeaders := getParam(r, "X-Response-Headers")
	customBodyHeader := getParam(r, "X-Response-Body")
	downloadName := getParam(r, "X-Response-Download")

	// 2. 设置CORS和默认响应头
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 3. 设置Location头
	if location != "" {
		w.Header().Set("Location", location)
	}

	// 4. 解析并设置自定义响应头
	if customHeaders != "" {
		headersMap := map[string]string{}
		err := json.Unmarshal([]byte(customHeaders), &headersMap)
		if err == nil {
			for k, v := range headersMap {
				w.Header().Set(k, v)
			}
		}
	}

	// 5. 设置Content-Type
	if respType == "xml" {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	} else if respType == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}

	// 6. 设置下载响应头
	if downloadName != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", downloadName))
	}

	// 7. 写响应状态码
	w.WriteHeader(statusCode)

	// HEAD 请求只返回响应头，不写响应体
	if r.Method == http.MethodHead {
		return
	}

	// 8. 响应体输出
	if customBodyHeader != "" {
		decodedBody, err := base64.StdEncoding.DecodeString(customBodyHeader)
		if err != nil {
			logger.Error("X-Response-Body base64 decoding failed", "error", err)
		} else {
			_, _ = w.Write(decodedBody)
			return
		}
	}

	// 9. 处理请求
	response, _ := processRequest(r)
	if respType == "xml" {
		if xmlData, err := toXML(response); err == nil {
			_, _ = w.Write(xmlData)
		} else {
			_, _ = w.Write([]byte("<error>xml encode error</error>"))
		}
	} else if respType == "text" {
		_, _ = w.Write([]byte(response.String()))
	} else {
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.Error("JSON encoding error", "err_msg", err)
		}
	}
}

// SSE Echo 处理
func handleSSEEchoRequest(w http.ResponseWriter, r *http.Request) {
	// 记录连接建立
	logger.Info("SSE连接建立",
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"url", r.URL.String(),
		"user_agent", r.UserAgent(),
	)

	// 记录连接断开
	defer func() {
		logger.Info("SSE连接断开",
			"remote_addr", r.RemoteAddr,
			"method", r.Method,
			"url", r.URL.String(),
		)
	}()

	// 支持 CORS 预检请求
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Response-Status-Code, X-Response-Status-Text, X-Response-Location, X-Response-Headers, X-Response-Type, X-Response-Sleep, X-Response-Body, X-Response-Sse-Count, X-Response-Mode")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 1. 解析自定义响应参数，优先Header
	statusCode := http.StatusOK
	if sc := getParam(r, "X-Response-Status-Code"); sc != "" {
		if code, err := parseStatusCode(sc); err == nil {
			statusCode = code
		}
	}

	location := getParam(r, "X-Response-Location")

	customBodyHeader := getParam(r, "X-Response-Body")
	sseCount := 100
	if cnt := getParam(r, "X-Response-Sse-Count"); cnt != "" {
		if c, err := strconv.Atoi(cnt); err == nil && c > 0 {
			sseCount = c
		}
	}
	sleepMs := 500
	if sleep := getParam(r, "X-Response-Sleep"); sleep != "" {
		if duration, err := strconv.Atoi(sleep); err == nil && duration > 0 {
			sleepMs = duration
		}
	}

	mode := strings.ToLower(getParam(r, "X-Response-Mode"))
	if mode == "" {
		mode = "default"
	}

	// 2. 设置CORS和SSE响应头
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	if location != "" {
		w.Header().Set("Location", location)
	}

	customHeaders := getParam(r, "X-Response-Headers")
	if customHeaders != "" {
		headersInfo, err := base64.StdEncoding.DecodeString(customHeaders)
		if err != nil {
			logger.Error("X-Response-Headers base64 decoding failed", "error", err)
			return
		}
		logger.Debug(string(headersInfo))
		headersMap := map[string]string{}
		err = json.Unmarshal(headersInfo, &headersMap)
		if err != nil {
			logger.Error("Unmarshal X-Response-Headers failed", "error", err)
			return
		}
		for k, v := range headersMap {
			w.Header().Set(k, v)
		}
	}

	w.WriteHeader(statusCode)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// 3. 处理自定义Body（优先级最高）
	if customBodyHeader != "" {
		decodedBody, err := base64.StdEncoding.DecodeString(customBodyHeader)
		if err != nil {
			logger.Error("X-Response-Body base64 decoding failed", "error", err)
			return
		}
		for i := 0; i < sseCount; i++ {
			logger.Debug("customBodyHeader", "data", string(decodedBody))
			flusher.Flush()
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	}

	// 4. 处理请求体和回显
	response, _ := processRequest(r)
	if mode == "react" {
		// SSE 不支持 react，自动降级为 user
		mode = "user"
	}
	if mode == "user" {
		// user模式，从队列取
		sseUserQueue.Lock()
		items := append([]any(nil), sseUserQueue.Items...)
		sseUserQueue.Unlock()
		for i := 0; i < sseCount && i < len(items); i++ {
			msgBytes, _ := json.Marshal(items[i])
			logger.Debug(string(msgBytes))
			flusher.Flush()
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	} else {
		// default模式，恢复原有逻辑
		for i := 0; i < sseCount; i++ {
			msg := map[string]any{
				"method":    response.Method,
				"url":       response.URL,
				"headers":   response.Headers,
				"body":      response.Body,
				"sse_index": i + 1,
				"sse_count": sseCount,
			}
			event := "message"
			if i%2 == 0 {
				event = "huang"
			}

			msgBytes, _ := json.Marshal(msg)
			_, _ = fmt.Fprintf(w, "id: %d\n", i)
			_, _ = fmt.Fprintf(w, "event: %s\n", event)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msgBytes)
			flusher.Flush()
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	}
}

// WebSocket Echo 处理
func handleWebSocketEchoRequest(w http.ResponseWriter, r *http.Request) {
	// 记录连接建立
	logger.Info("WebSocket连接建立",
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"url", r.URL.String(),
		"user_agent", r.UserAgent(),
	)

	upgrader := Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	responseHeader := http.Header{}
	customHeaders := getParam(r, "X-Response-Headers")
	if customHeaders != "" {
		headersInfo, err := base64.StdEncoding.DecodeString(customHeaders)
		if err != nil {
			logger.Error("X-Response-Headers base64 decoding failed", "error", err)
			return
		}
		logger.Debug(string(headersInfo))
		headersMap := map[string]string{}
		err = json.Unmarshal(headersInfo, &headersMap)
		if err != nil {
			logger.Error("Unmarshal X-Response-Headers failed", "error", err)
			return
		}
		for k, v := range headersMap {
			responseHeader.Set(k, v)
		}
	}

	conn, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		logger.Error("WebSocket升级失败",
			"remote_addr", r.RemoteAddr,
			"error", err,
		)
		logger.Error("WebSocket upgrade error", "error_msg", err)
		return
	}
	defer func() {
		logger.Info("WebSocket连接断开",
			"remote_addr", r.RemoteAddr,
			"method", r.Method,
			"url", r.URL.String(),
		)
		_ = conn.Close()
	}()

	// 设置 Ping 处理函数
	conn.SetPingHandler(func(appData string) error {
		logger.Debug("收到 Ping,回复 Pong:", "data", appData)
		// 可以在此处添加自定义逻辑
		return nil
	})

	// 设置 Pong 处理函数
	conn.SetPongHandler(func(appData string) error {
		logger.Debug("收到 Pong，连接正常:", "data", appData)
		// 更新连接的最后活动时间
		return nil
	})

	go func() {
		// 定期发送 Ping 帧
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				logger.Debug("send_ping")
				// 发送 Ping 帧
				if err := conn.WriteControl(PingMessage, []byte("my-heartbeat"), time.Now().Add(10*time.Second)); err != nil {
					logger.Error("send ping failed", "error_msg", err)
					return
				}
			}
		}
	}()

	// 解析自定义参数
	customBodyHeader := getParam(r, "X-Response-Body")
	wsCount := 100
	if cnt := getParam(r, "X-Response-Websocket-Count"); cnt != "" {
		if c, err := strconv.Atoi(cnt); err == nil && c > 0 {
			wsCount = c
		}
	}
	sleepMs := 500
	if sleep := getParam(r, "X-Response-Sleep"); sleep != "" {
		if duration, err := strconv.Atoi(sleep); err == nil && duration > 0 {
			sleepMs = duration
		}
	}

	mode := strings.ToLower(getParam(r, "X-Response-Mode"))
	if mode == "" {
		mode = "default"
	}

	// WebSocket只支持GET方法，其他方法通过header传递
	// 处理自定义Body（优先级最高）
	if customBodyHeader != "" {
		decodedBody, err := base64.StdEncoding.DecodeString(customBodyHeader)
		if err != nil {
			logger.Error("X-Response-Body base64 decoding failed", "error", err)
			return
		}
		for i := 0; i < wsCount; i++ {
			err := conn.WriteMessage(TextMessage, decodedBody)
			if err != nil {
				logger.Error("WebSocket写入失败",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				logger.Error("WebSocket write error", "error_msg", err)
				return
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	}

	// 处理请求体和回显
	response, _ := processRequest(r)
	if mode == "react" {
		// 新增：前端发消息，服务端收到后写入 wsReactCh
		go func() {
			for {
				type_, msg, err := conn.ReadMessage()
				if err != nil {
					logger.Info("WebSocket客户端断开",
						"remote_addr", r.RemoteAddr,
						"error", err,
					)
					return
				}
				if type_ == TextMessage || type_ == BinaryMessage {
					logger.Info("WebSocket收到客户端消息",
						"remote_addr", r.RemoteAddr,
						"message_type", type_,
						"message_length", len(msg),
					)
					wsReactCh <- string(msg)
				}
			}
		}()
		for i := 0; i < wsCount; i++ {
			select {
			case v := <-wsReactCh:
				msgBytes, _ := json.Marshal(v)
				err := conn.WriteMessage(TextMessage, msgBytes)
				if err != nil {
					logger.Error("WebSocket写入失败",
						"remote_addr", r.RemoteAddr,
						"error", err,
					)
					logger.Error("WebSocket write error", "error_msg", err)
					return
				}
			case <-r.Context().Done():
				return
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	} else if mode == "user" {
		go func() {
			defer conn.Close()
			for {
				// 注意：此处必须调用 ReadMessage 或类似方法
				// 否则控制帧（如 Pong）可能不会被触发
				_, _, err := conn.ReadMessage()
				if err != nil {
					logger.Error("read msg error", "error_msg", err)
					return
				}
			}
		}()

		wsUserQueue.Lock()
		items := append([]any(nil), wsUserQueue.Items...)
		wsUserQueue.Unlock()
		for i := 0; i < wsCount && i < len(items); i++ {
			msgBytes, _ := json.Marshal(items[i])
			err := conn.WriteMessage(TextMessage, msgBytes)
			if err != nil {
				logger.Error("WebSocket写入失败",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				logger.Error("WebSocket write error", "error_msg", err)
				return
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	} else {

		go func() {
			defer conn.Close()
			for {
				// 注意：此处必须调用 ReadMessage 或类似方法
				// 否则控制帧（如 Pong）可能不会被触发
				_, _, err := conn.ReadMessage()
				if err != nil {
					logger.Error("WebSocket read error", "error_msg", err)
					return
				}
				// 处理消息内容
			}
		}()

		data, err := embeddedFS.ReadFile("favicon.ico")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// default模式，恢复原有逻辑
		for i := 0; i < wsCount; i++ {
			msg := map[string]any{
				"method":   response.Method,
				"url":      response.URL,
				"headers":  response.Headers,
				"body":     response.Body,
				"ws_index": i + 1,
				"ws_count": wsCount,
			}
			msgBytes, _ := json.Marshal(msg)
			var err error
			if i%2 == 0 {
				err = conn.WriteMessage(TextMessage, msgBytes)
			} else {
				err = conn.WriteMessage(BinaryMessage, data)
			}
			if err != nil {
				logger.Error("WebSocket写入失败",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				logger.Error("WebSocket write error", "error_msg", err)
				return
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		return
	}
}

// 处理 CONNECT 请求
func handleConnect(w http.ResponseWriter, r *http.Request) {
	// 使用示例:
	// yum -y install nmap-ncat
	// ssh -o "ProxyCommand ncat --proxy 192.168.150.110:8080 --proxy-type http %h %p" root@192.168.150.88
	// curl -k -x http://192.168.150.110:8080 https://192.168.150.88:6443

	// 获取目标地址 (host:port)
	target := r.URL.Host
	logger.Info("Connect Proxy:", "target", target)
	if _, _, err := net.SplitHostPort(target); err != nil {
		// 补充默认端口
		if strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "443")
			logger.Info("Connect Proxy Https:", "target", target)
			fmt.Println("target-A->:", target)
		} else {
			target = net.JoinHostPort(target, "80")
			logger.Info("Connect Proxy Http:", "target", target)
		}
	}

	// 创建到目标服务器的连接
	dialer := net.Dialer{Timeout: 10 * time.Second}
	targetConn, err := dialer.DialContext(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "Failed to connect to target: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	// Hijack 获取原始客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// 发送 CONNECT 成功响应
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	logger.Info("Connection established", "target", target)

	// 启动双向数据转发
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// 客户端 -> 目标服务器
	go func() {
		defer cancel()
		_, _ = io.Copy(targetConn, clientConn)
	}()

	// 目标服务器 -> 客户端
	go func() {
		defer cancel()
		_, _ = io.Copy(clientConn, targetConn)
	}()

	// 等待连接结束
	<-ctx.Done()
	logger.Info("Connection closed", "target", target)
}

func processRequest(r *http.Request) (*EchoResponse, int) {
	// 获取请求完整URL
	fullURL := getFullURL(r)

	// 处理请求头
	var headers []HeaderKV
	for k, v := range r.Header {
		headers = append(headers, HeaderKV{Key: k, Value: strings.Join(v, ", ")})
	}

	// 检测请求体类型并处理
	contentType := r.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)

	// 处理不同类型请求体
	var bodyContent any
	bodySize := int64(0)

	// 当请求包含Body时（POST, PUT, PATCH等）
	if r.Body != http.NoBody {
		// 保存原始请求体以备后续读取
		bodyData, _ := io.ReadAll(r.Body)
		bodySize = int64(len(bodyData))
		r.Body = io.NopCloser(bytes.NewReader(bodyData))

		switch {
		case strings.HasPrefix(mediaType, "multipart/form-data"):
			bodyContent = processMultipartForm(r)
		case strings.HasPrefix(mediaType, "application/x-www-form-urlencoded"):
			bodyContent = processForm(r)
		case isTextContentType(mediaType) || contentType == "":
			bodyContent = string(bodyData)
		default:
			// 二进制或未知类型
			bodyContent = &BinaryBody{
				Size:       bodySize,
				SizeHuman:  formatSize(bodySize),
				ContentHex: fmt.Sprintf("%x", bodyData[:min(len(bodyData), 16)]),
			}
		}
	} else {
		bodyContent = nil
	}

	return &EchoResponse{
		Method:  r.Method,
		URL:     fullURL,
		Headers: headers,
		Body:    bodyContent,
	}, http.StatusOK
}

// EchoResponse Echo响应结构
type EchoResponse struct {
	XMLName xml.Name   `json:"-" xml:"response"`
	Method  string     `json:"method" xml:"method"`
	URL     string     `json:"url" xml:"url"`
	Headers []HeaderKV `json:"headers" xml:"headers>header"`
	Body    any        `json:"body,omitempty" xml:"body,omitempty"`
}

type HeaderKV struct {
	Key   string `json:"key" xml:"key,attr"`
	Value string `json:"value" xml:",chardata"`
}

// FileMetaInfo 文件信息结构
type FileMetaInfo struct {
	XMLName     xml.Name `json:"-" xml:"file"`
	Filename    string   `json:"filename" xml:"filename"`
	Size        int64    `json:"size" xml:"size"`
	SizeHuman   string   `json:"size_human" xml:"size_human"`
	ContentType string   `json:"content_type" xml:"content_type"`
}

// FormField 表单字段结构
type FormField struct {
	XMLName xml.Name `json:"-" xml:"field"`
	Name    string   `json:"name" xml:"name"`
	Value   any      `json:"value" xml:"value"`
}

// BinaryBody 二进制响应结构
type BinaryBody struct {
	XMLName    xml.Name `json:"-" xml:"binary"`
	Size       int64    `json:"size" xml:"size"`
	SizeHuman  string   `json:"size_human" xml:"size_human"`
	ContentHex string   `json:"content_hex" xml:"content_hex"`
}

// 处理multipart/form-data请求
func processMultipartForm(r *http.Request) map[string]any {
	// 解析multipart表单
	err := r.ParseMultipartForm(maxMemory)
	if err != nil {
		return map[string]any{"error": "Failed to parse form-data: " + err.Error()}
	}

	formContent := make(map[string]any)
	formContent["fields"] = []FormField{}
	formContent["files"] = []FileMetaInfo{}

	// 处理文本字段
	for name, values := range r.MultipartForm.Value {
		for _, value := range values {
			formContent["fields"] = append(formContent["fields"].([]FormField), FormField{
				Name:  name,
				Value: value,
			})
		}
	}

	// 处理文件字段
	for _, headers := range r.MultipartForm.File {
		for _, header := range headers {

			// 获取文件信息
			fileInfo := FileMetaInfo{
				Filename:    header.Filename,
				Size:        header.Size,
				SizeHuman:   formatSize(header.Size),
				ContentType: header.Header.Get("Content-Type"),
			}

			formContent["files"] = append(formContent["files"].([]FileMetaInfo), fileInfo)

			// 如指定了uploadDir且目录存在,则保存文件
			if uploadDir != "" {
				if info, err := os.Stat(uploadDir); err == nil && info.IsDir() {
					file, err := header.Open()
					if err == nil {
						outPath := filepath.Join(uploadDir, header.Filename)
						outFile, err := os.Create(outPath)
						if err == nil {
							_, _ = io.Copy(outFile, file)
							_ = outFile.Close()
						}
						_ = file.Close()
					}
				}
			}
		}
	}

	return formContent
}

// 处理x-www-form-urlencoded请求
func processForm(r *http.Request) map[string]any {
	err := r.ParseForm()
	if err != nil {
		return map[string]any{"error": "Failed to parse form: " + err.Error()}
	}

	formContent := make(map[string]any)
	formContent["fields"] = []FormField{}

	for name, values := range r.Form {
		for _, value := range values {
			formContent["fields"] = append(formContent["fields"].([]FormField), FormField{
				Name:  name,
				Value: value,
			})
		}
	}

	return formContent
}

// 获取完整URL（包含查询参数）
func getFullURL(r *http.Request) string {
	u := r.URL
	urlObj := &url.URL{
		Scheme:   "http", // 实际环境中应考虑HTTPS
		Host:     r.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}
	return urlObj.String()
}

// 检测是否为文本内容类型
func isTextContentType(mediaType string) bool {
	return strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" ||
		mediaType == "application/xml" ||
		mediaType == "application/javascript" ||
		mediaType == "application/xhtml+xml"
}

// 格式化字节大小
func formatSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
}

// 解析状态码
func parseStatusCode(s string) (int, error) {
	var code int
	_, err := fmt.Sscanf(s, "%d", &code)
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("invalid status code")
	}
	return code, nil
}

// toXML使用encoding/xml
func toXML(v any) ([]byte, error) {
	return xml.MarshalIndent(v, "", "  ")
}

func (e *EchoResponse) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Method: %s\n", e.Method))
	sb.WriteString(fmt.Sprintf("URL: %s\n", e.URL))
	sb.WriteString("\n--- Headers ---\n")
	for _, h := range e.Headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", h.Key, h.Value))
	}

	sb.WriteString("\n--- Body ---\n")
	if e.Body != nil {
		switch v := e.Body.(type) {
		case string:
			sb.WriteString(v)
		default:
			bodyBytes, err := json.MarshalIndent(e.Body, "", "  ")
			if err != nil {
				sb.WriteString(fmt.Sprintf("[Could not serialize body: %v]", err))
			} else {
				sb.Write(bodyBytes)
			}
		}
	} else {
		sb.WriteString("[empty]")
	}
	return sb.String()
}

// 获取参数优先级：Header > URL参数
func getParam(r *http.Request, key string) string {
	h := r.Header.Get(key)
	if h != "" {
		return h
	}
	return r.URL.Query().Get(key)
}

// /api/sse/set
func handleSSESet(w http.ResponseWriter, r *http.Request) {
	var items []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	sseUserQueue.Lock()
	sseUserQueue.Items = nil
	for _, item := range items {
		if v, ok := item["value"]; ok {
			sseUserQueue.Items = append(sseUserQueue.Items, v)
		}
	}
	sseUserQueue.Unlock()
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}

// /api/ws/set
func handleWSSet(w http.ResponseWriter, r *http.Request) {
	var items []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	wsUserQueue.Lock()
	wsUserQueue.Items = nil
	for _, item := range items {
		if v, ok := item["value"]; ok {
			wsUserQueue.Items = append(wsUserQueue.Items, v)
		}
	}
	wsUserQueue.Unlock()
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}

// ====================================================================================================
//
// # WebSocket库
//
// ====================================================================================================
// ErrBadHandshake is returned when the server response to opening handshake is
// invalid.
var ErrBadHandshake = errors.New("websocket: bad handshake")

var errInvalidCompression = errors.New("websocket: invalid compression negotiation")

// NewClient creates a new client connection using the given net connection.
// The URL u specifies the host and request URI. Use requestHeader to specify
// the origin (Origin), subprotocols (Sec-WebSocket-Protocol) and cookies
// (Cookie). Use the response.Header to get the selected subprotocol
// (Sec-WebSocket-Protocol) and cookies (Set-Cookie).
//
// If the WebSocket handshake fails, ErrBadHandshake is returned along with a
// non-nil *http.Response so that callers can handle redirects, authentication,
// etc.
//
// Deprecated: Use Dialer instead.
func NewClient(netConn net.Conn, u *url.URL, requestHeader http.Header, readBufSize, writeBufSize int) (c *Conn, response *http.Response, err error) {
	d := Dialer{
		ReadBufferSize:  readBufSize,
		WriteBufferSize: writeBufSize,
		NetDial: func(net, addr string) (net.Conn, error) {
			return netConn, nil
		},
	}
	return d.Dial(u.String(), requestHeader)
}

// A Dialer contains options for connecting to WebSocket server.
//
// It is safe to call Dialer's methods concurrently.
type Dialer struct {
	// NetDial specifies the dial function for creating TCP connections. If
	// NetDial is nil, net.Dialer DialContext is used.
	NetDial func(network, addr string) (net.Conn, error)

	// NetDialContext specifies the dial function for creating TCP connections. If
	// NetDialContext is nil, NetDial is used.
	NetDialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// NetDialTLSContext specifies the dial function for creating TLS/TCP connections. If
	// NetDialTLSContext is nil, NetDialContext is used.
	// If NetDialTLSContext is set, Dial assumes the TLS handshake is done there and
	// TLSClientConfig is ignored.
	NetDialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*http.Request) (*url.URL, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	// If either NetDialTLS or NetDialTLSContext are set, Dial assumes the TLS handshake
	// is done there and TLSClientConfig is ignored.
	TLSClientConfig *tls.Config

	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes in bytes. If a buffer
	// size is zero, then a useful default size is used. The I/O buffer sizes
	// do not limit the size of the messages that can be sent or received.
	ReadBufferSize, WriteBufferSize int

	// WriteBufferPool is a pool of buffers for write operations. If the value
	// is not set, then write buffers are allocated to the connection for the
	// lifetime of the connection.
	//
	// A pool is most useful when the application has a modest volume of writes
	// across a large number of connections.
	//
	// Applications should use a single pool for each unique value of
	// WriteBufferSize.
	WriteBufferPool BufferPool

	// Subprotocols specifies the client's requested subprotocols.
	Subprotocols []string

	// EnableCompression specifies if the client should attempt to negotiate
	// per message compression (RFC 7692). Setting this value to true does not
	// guarantee that compression will be supported. Currently only "no context
	// takeover" modes are supported.
	EnableCompression bool

	// Jar specifies the cookie jar.
	// If Jar is nil, cookies are not sent in requests and ignored
	// in responses.
	Jar http.CookieJar
}

// Dial creates a new client connection by calling DialContext with a background context.
func (d *Dialer) Dial(urlStr string, requestHeader http.Header) (*Conn, *http.Response, error) {
	return d.DialContext(context.Background(), urlStr, requestHeader)
}

var errMalformedURL = errors.New("malformed ws or wss URL")

func hostPortNoPort(u *url.URL) (hostPort, hostNoPort string) {
	hostPort = u.Host
	hostNoPort = u.Host
	if i := strings.LastIndex(u.Host, ":"); i > strings.LastIndex(u.Host, "]") {
		hostNoPort = hostNoPort[:i]
	} else {
		switch u.Scheme {
		case "wss":
			hostPort += ":443"
		case "https":
			hostPort += ":443"
		default:
			hostPort += ":80"
		}
	}
	return hostPort, hostNoPort
}

// DefaultDialer is a dialer with all fields set to the default values.
var DefaultDialer = &Dialer{
	Proxy:            http.ProxyFromEnvironment,
	HandshakeTimeout: 45 * time.Second,
}

// nilDialer is dialer to use when receiver is nil.
var nilDialer = *DefaultDialer

// DialContext creates a new client connection. Use requestHeader to specify the
// origin (Origin), subprotocols (Sec-WebSocket-Protocol) and cookies (Cookie).
// Use the response.Header to get the selected subprotocol
// (Sec-WebSocket-Protocol) and cookies (Set-Cookie).
//
// The context will be used in the request and in the Dialer.
//
// If the WebSocket handshake fails, ErrBadHandshake is returned along with a
// non-nil *http.Response so that callers can handle redirects, authentication,
// etcetera. The response body may not contain the entire response and does not
// need to be closed by the application.
func (d *Dialer) DialContext(ctx context.Context, urlStr string, requestHeader http.Header) (*Conn, *http.Response, error) {
	if d == nil {
		d = &nilDialer
	}

	challengeKey, err := generateChallengeKey()
	if err != nil {
		return nil, nil, err
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, err
	}

	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	default:
		return nil, nil, errMalformedURL
	}

	if u.User != nil {
		// User name and password are not allowed in websocket URIs.
		return nil, nil, errMalformedURL
	}

	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       u.Host,
	}
	req = req.WithContext(ctx)

	// Set the cookies present in the cookie jar of the dialer
	if d.Jar != nil {
		for _, cookie := range d.Jar.Cookies(u) {
			req.AddCookie(cookie)
		}
	}

	// Set the request headers using the capitalization for names and values in
	// RFC examples. Although the capitalization shouldn't matter, there are
	// servers that depend on it. The Header.Set method is not used because the
	// method canonicalizes the header names.
	req.Header["Upgrade"] = []string{"websocket"}
	req.Header["Connection"] = []string{"Upgrade"}
	req.Header["Sec-WebSocket-Key"] = []string{challengeKey}
	req.Header["Sec-WebSocket-Version"] = []string{"13"}
	if len(d.Subprotocols) > 0 {
		req.Header["Sec-WebSocket-Protocol"] = []string{strings.Join(d.Subprotocols, ", ")}
	}
	for k, vs := range requestHeader {
		switch {
		case k == "Host":
			if len(vs) > 0 {
				req.Host = vs[0]
			}
		case k == "Upgrade" ||
			k == "Connection" ||
			k == "Sec-Websocket-Key" ||
			k == "Sec-Websocket-Version" ||
			k == "Sec-Websocket-Extensions" ||
			(k == "Sec-Websocket-Protocol" && len(d.Subprotocols) > 0):
			return nil, nil, errors.New("websocket: duplicate header not allowed: " + k)
		case k == "Sec-Websocket-Protocol":
			req.Header["Sec-WebSocket-Protocol"] = vs
		default:
			req.Header[k] = vs
		}
	}

	if d.EnableCompression {
		req.Header["Sec-WebSocket-Extensions"] = []string{"permessage-deflate; server_no_context_takeover; client_no_context_takeover"}
	}

	if d.HandshakeTimeout != 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, d.HandshakeTimeout)
		defer cancel()
	}

	var netDial netDialerFunc
	switch {
	case u.Scheme == "https" && d.NetDialTLSContext != nil:
		netDial = d.NetDialTLSContext
	case d.NetDialContext != nil:
		netDial = d.NetDialContext
	case d.NetDial != nil:
		netDial = func(ctx context.Context, net, addr string) (net.Conn, error) {
			return d.NetDial(net, addr)
		}
	default:
		netDial = (&net.Dialer{}).DialContext
	}

	// If needed, wrap the dial function to set the connection deadline.
	if deadline, ok := ctx.Deadline(); ok {
		forwardDial := netDial
		netDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := forwardDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			err = c.SetDeadline(deadline)
			if err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		}
	}

	// If needed, wrap the dial function to connect through a proxy.
	if d.Proxy != nil {
		proxyURL, err := d.Proxy(req)
		if err != nil {
			return nil, nil, err
		}
		if proxyURL != nil {
			netDial, err = proxyFromURL(proxyURL, netDial)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	hostPort, hostNoPort := hostPortNoPort(u)
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(hostPort)
	}

	netConn, err := netDial(ctx, "tcp", hostPort)
	if err != nil {
		return nil, nil, err
	}
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{
			Conn: netConn,
		})
	}

	// Close the network connection when returning an error. The variable
	// netConn is set to nil before the success return at the end of the
	// function.
	defer func() {
		if netConn != nil {
			// It's safe to ignore the error from Close() because this code is
			// only executed when returning a more important error to the
			// application.
			_ = netConn.Close()
		}
	}()

	if u.Scheme == "https" && d.NetDialTLSContext == nil {
		// If NetDialTLSContext is set, assume that the TLS handshake has already been done

		cfg := cloneTLSConfig(d.TLSClientConfig)
		if cfg.ServerName == "" {
			cfg.ServerName = hostNoPort
		}
		tlsConn := tls.Client(netConn, cfg)
		netConn = tlsConn

		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		err := doHandshake(ctx, tlsConn, cfg)
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tlsConn.ConnectionState(), err)
		}

		if err != nil {
			return nil, nil, err
		}
	}

	conn := newConn(netConn, false, d.ReadBufferSize, d.WriteBufferSize, d.WriteBufferPool, nil, nil)

	if err := req.Write(netConn); err != nil {
		return nil, nil, err
	}

	if trace != nil && trace.GotFirstResponseByte != nil {
		if peek, err := conn.br.Peek(1); err == nil && len(peek) == 1 {
			trace.GotFirstResponseByte()
		}
	}

	resp, err := http.ReadResponse(conn.br, req)
	if err != nil {
		if d.TLSClientConfig != nil {
			for _, proto := range d.TLSClientConfig.NextProtos {
				if proto != "http/1.1" {
					return nil, nil, fmt.Errorf(
						"websocket: protocol %q was given but is not supported;"+
							"sharing tls.Config with net/http Transport can cause this error: %w",
						proto, err,
					)
				}
			}
		}
		return nil, nil, err
	}

	if d.Jar != nil {
		if rc := resp.Cookies(); len(rc) > 0 {
			d.Jar.SetCookies(u, rc)
		}
	}

	if resp.StatusCode != 101 ||
		!tokenListContainsValue(resp.Header, "Upgrade", "websocket") ||
		!tokenListContainsValue(resp.Header, "Connection", "upgrade") ||
		resp.Header.Get("Sec-Websocket-Accept") != computeAcceptKey(challengeKey) {
		// Before closing the network connection on return from this
		// function, slurp up some of the response to aid application
		// debugging.
		buf := make([]byte, 1024)
		n, _ := io.ReadFull(resp.Body, buf)
		resp.Body = io.NopCloser(bytes.NewReader(buf[:n]))
		return nil, resp, ErrBadHandshake
	}

	for _, ext := range parseExtensions(resp.Header) {
		if ext[""] != "permessage-deflate" {
			continue
		}
		_, snct := ext["server_no_context_takeover"]
		_, cnct := ext["client_no_context_takeover"]
		if !snct || !cnct {
			return nil, resp, errInvalidCompression
		}
		conn.newCompressionWriter = compressNoContextTakeover
		conn.newDecompressionReader = decompressNoContextTakeover
		break
	}

	resp.Body = io.NopCloser(bytes.NewReader([]byte{}))
	conn.subprotocol = resp.Header.Get("Sec-Websocket-Protocol")

	if err := netConn.SetDeadline(time.Time{}); err != nil {
		return nil, resp, err
	}

	// Success! Set netConn to nil to stop the deferred function above from
	// closing the network connection.
	netConn = nil

	return conn, resp, nil
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func doHandshake(ctx context.Context, tlsConn *tls.Conn, cfg *tls.Config) error {
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	if !cfg.InsecureSkipVerify {
		if err := tlsConn.VerifyHostname(cfg.ServerName); err != nil {
			return err
		}
	}
	return nil
}

//----------------------------------------------------------------------------------------------------

const (
	minCompressionLevel     = -2 // flate.HuffmanOnly not defined in Go < 1.6
	maxCompressionLevel     = flate.BestCompression
	defaultCompressionLevel = 1
)

var (
	flateWriterPools [maxCompressionLevel - minCompressionLevel + 1]sync.Pool
	flateReaderPool  = sync.Pool{New: func() any {
		return flate.NewReader(nil)
	}}
)

func decompressNoContextTakeover(r io.Reader) io.ReadCloser {
	const tail =
	// Add four bytes as specified in RFC
	"\x00\x00\xff\xff" +
		// Add final block to squelch unexpected EOF error from flate reader.
		"\x01\x00\x00\xff\xff"

	fr, _ := flateReaderPool.Get().(io.ReadCloser)
	mr := io.MultiReader(r, strings.NewReader(tail))
	if err := fr.(flate.Resetter).Reset(mr, nil); err != nil {
		// Reset never fails, but handle error in case that changes.
		fr = flate.NewReader(mr)
	}
	return &flateReadWrapper{fr}
}

func isValidCompressionLevel(level int) bool {
	return minCompressionLevel <= level && level <= maxCompressionLevel
}

func compressNoContextTakeover(w io.WriteCloser, level int) io.WriteCloser {
	p := &flateWriterPools[level-minCompressionLevel]
	tw := &truncWriter{w: w}
	fw, _ := p.Get().(*flate.Writer)
	if fw == nil {
		fw, _ = flate.NewWriter(tw, level)
	} else {
		fw.Reset(tw)
	}
	return &flateWriteWrapper{fw: fw, tw: tw, p: p}
}

// truncWriter is an io.Writer that writes all but the last four bytes of the
// stream to another io.Writer.
type truncWriter struct {
	w io.WriteCloser
	n int
	p [4]byte
}

func (w *truncWriter) Write(p []byte) (int, error) {
	n := 0

	// fill buffer first for simplicity.
	if w.n < len(w.p) {
		n = copy(w.p[w.n:], p)
		p = p[n:]
		w.n += n
		if len(p) == 0 {
			return n, nil
		}
	}

	m := len(p)
	if m > len(w.p) {
		m = len(w.p)
	}

	if nn, err := w.w.Write(w.p[:m]); err != nil {
		return n + nn, err
	}

	copy(w.p[:], w.p[m:])
	copy(w.p[len(w.p)-m:], p[len(p)-m:])
	nn, err := w.w.Write(p[:len(p)-m])
	return n + nn, err
}

type flateWriteWrapper struct {
	fw *flate.Writer
	tw *truncWriter
	p  *sync.Pool
}

func (w *flateWriteWrapper) Write(p []byte) (int, error) {
	if w.fw == nil {
		return 0, errWriteClosed
	}
	return w.fw.Write(p)
}

func (w *flateWriteWrapper) Close() error {
	if w.fw == nil {
		return errWriteClosed
	}
	err1 := w.fw.Flush()
	w.p.Put(w.fw)
	w.fw = nil
	if w.tw.p != [4]byte{0, 0, 0xff, 0xff} {
		return errors.New("websocket: internal error, unexpected bytes at end of flate stream")
	}
	err2 := w.tw.w.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

type flateReadWrapper struct {
	fr io.ReadCloser
}

func (r *flateReadWrapper) Read(p []byte) (int, error) {
	if r.fr == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := r.fr.Read(p)
	if err == io.EOF {
		// Preemptively place the reader back in the pool. This helps with
		// scenarios where the application does not call NextReader() soon after
		// this final read.
		r.Close()
	}
	return n, err
}

func (r *flateReadWrapper) Close() error {
	if r.fr == nil {
		return io.ErrClosedPipe
	}
	err := r.fr.Close()
	flateReaderPool.Put(r.fr)
	r.fr = nil
	return err
}

//----------------------------------------------------------------------------------------------------

const (
	// Frame header byte 0 bits from Section 5.2 of RFC 6455
	finalBit = 1 << 7
	rsv1Bit  = 1 << 6
	rsv2Bit  = 1 << 5
	rsv3Bit  = 1 << 4

	// Frame header byte 1 bits from Section 5.2 of RFC 6455
	maskBit = 1 << 7

	maxFrameHeaderSize         = 2 + 8 + 4 // Fixed header + length + mask
	maxControlFramePayloadSize = 125

	writeWait = time.Second

	defaultReadBufferSize  = 4096
	defaultWriteBufferSize = 4096

	continuationFrame = 0
	noFrame           = -1
)

// Close codes defined in RFC 6455, section 11.7.
const (
	CloseNormalClosure           = 1000
	CloseGoingAway               = 1001
	CloseProtocolError           = 1002
	CloseUnsupportedData         = 1003
	CloseNoStatusReceived        = 1005
	CloseAbnormalClosure         = 1006
	CloseInvalidFramePayloadData = 1007
	ClosePolicyViolation         = 1008
	CloseMessageTooBig           = 1009
	CloseMandatoryExtension      = 1010
	CloseInternalServerErr       = 1011
	CloseServiceRestart          = 1012
	CloseTryAgainLater           = 1013
	CloseTLSHandshake            = 1015
)

// The message types are defined in RFC 6455, section 11.8.
const (
	// TextMessage denotes a text data message. The text message payload is
	// interpreted as UTF-8 encoded text data.
	TextMessage = 1

	// BinaryMessage denotes a binary data message.
	BinaryMessage = 2

	// CloseMessage denotes a close control message. The optional message
	// payload contains a numeric code and text. Use the FormatCloseMessage
	// function to format a close message payload.
	CloseMessage = 8

	// PingMessage denotes a ping control message. The optional message payload
	// is UTF-8 encoded text.
	PingMessage = 9

	// PongMessage denotes a pong control message. The optional message payload
	// is UTF-8 encoded text.
	PongMessage = 10
)

// ErrCloseSent is returned when the application writes a message to the
// connection after sending a close message.
var ErrCloseSent = errors.New("websocket: close sent")

// ErrReadLimit is returned when reading a message that is larger than the
// read limit set for the connection.
var ErrReadLimit = errors.New("websocket: read limit exceeded")

// netError satisfies the net Error interface.
type netError struct {
	msg       string
	temporary bool
	timeout   bool
}

func (e *netError) Error() string   { return e.msg }
func (e *netError) Temporary() bool { return e.temporary }
func (e *netError) Timeout() bool   { return e.timeout }

// CloseError represents a close message.
type CloseError struct {
	// Code is defined in RFC 6455, section 11.7.
	Code int

	// Text is the optional text payload.
	Text string
}

func (e *CloseError) Error() string {
	s := []byte("websocket: close ")
	s = strconv.AppendInt(s, int64(e.Code), 10)
	switch e.Code {
	case CloseNormalClosure:
		s = append(s, " (normal)"...)
	case CloseGoingAway:
		s = append(s, " (going away)"...)
	case CloseProtocolError:
		s = append(s, " (protocol error)"...)
	case CloseUnsupportedData:
		s = append(s, " (unsupported data)"...)
	case CloseNoStatusReceived:
		s = append(s, " (no status)"...)
	case CloseAbnormalClosure:
		s = append(s, " (abnormal closure)"...)
	case CloseInvalidFramePayloadData:
		s = append(s, " (invalid payload data)"...)
	case ClosePolicyViolation:
		s = append(s, " (policy violation)"...)
	case CloseMessageTooBig:
		s = append(s, " (message too big)"...)
	case CloseMandatoryExtension:
		s = append(s, " (mandatory extension missing)"...)
	case CloseInternalServerErr:
		s = append(s, " (internal server error)"...)
	case CloseTLSHandshake:
		s = append(s, " (TLS handshake error)"...)
	}
	if e.Text != "" {
		s = append(s, ": "...)
		s = append(s, e.Text...)
	}
	return string(s)
}

// IsCloseError returns boolean indicating whether the error is a *CloseError
// with one of the specified codes.
func IsCloseError(err error, codes ...int) bool {
	if e, ok := err.(*CloseError); ok {
		for _, code := range codes {
			if e.Code == code {
				return true
			}
		}
	}
	return false
}

// IsUnexpectedCloseError returns boolean indicating whether the error is a
// *CloseError with a code not in the list of expected codes.
func IsUnexpectedCloseError(err error, expectedCodes ...int) bool {
	if e, ok := err.(*CloseError); ok {
		for _, code := range expectedCodes {
			if e.Code == code {
				return false
			}
		}
		return true
	}
	return false
}

var (
	errWriteTimeout        = &netError{msg: "websocket: write timeout", timeout: true, temporary: true}
	errUnexpectedEOF       = &CloseError{Code: CloseAbnormalClosure, Text: io.ErrUnexpectedEOF.Error()}
	errBadWriteOpCode      = errors.New("websocket: bad write message type")
	errWriteClosed         = errors.New("websocket: write closed")
	errInvalidControlFrame = errors.New("websocket: invalid control frame")
)

// maskRand is an io.Reader for generating mask bytes. The reader is initialized
// to crypto/rand Reader. Tests swap the reader to a math/rand reader for
// reproducible results.
var maskRand = cryptorand.Reader

// newMaskKey returns a new 32 bit value for masking client frames.
func newMaskKey() [4]byte {
	var k [4]byte
	_, _ = io.ReadFull(maskRand, k[:])
	return k
}

func isControl(frameType int) bool {
	return frameType == CloseMessage || frameType == PingMessage || frameType == PongMessage
}

func isData(frameType int) bool {
	return frameType == TextMessage || frameType == BinaryMessage
}

var validReceivedCloseCodes = map[int]bool{
	// see http://www.iana.org/assignments/websocket/websocket.xhtml#close-code-number

	CloseNormalClosure:           true,
	CloseGoingAway:               true,
	CloseProtocolError:           true,
	CloseUnsupportedData:         true,
	CloseNoStatusReceived:        false,
	CloseAbnormalClosure:         false,
	CloseInvalidFramePayloadData: true,
	ClosePolicyViolation:         true,
	CloseMessageTooBig:           true,
	CloseMandatoryExtension:      true,
	CloseInternalServerErr:       true,
	CloseServiceRestart:          true,
	CloseTryAgainLater:           true,
	CloseTLSHandshake:            false,
}

func isValidReceivedCloseCode(code int) bool {
	return validReceivedCloseCodes[code] || (code >= 3000 && code <= 4999)
}

// BufferPool represents a pool of buffers. The *sync.Pool type satisfies this
// interface.  The type of the value stored in a pool is not specified.
type BufferPool interface {
	// Get gets a value from the pool or returns nil if the pool is empty.
	Get() any
	// Put adds a value to the pool.
	Put(any)
}

// writePoolData is the type added to the write buffer pool. This wrapper is
// used to prevent applications from peeking at and depending on the values
// added to the pool.
type writePoolData struct{ buf []byte }

// The Conn type represents a WebSocket connection.
type Conn struct {
	conn        net.Conn
	isServer    bool
	subprotocol string

	// Write fields
	mu            chan struct{} // used as mutex to protect write to conn
	writeBuf      []byte        // frame is constructed in this buffer.
	writePool     BufferPool
	writeBufSize  int
	writeDeadline time.Time
	writer        io.WriteCloser // the current writer returned to the application
	isWriting     bool           // for best-effort concurrent write detection

	writeErrMu sync.Mutex
	writeErr   error

	enableWriteCompression bool
	compressionLevel       int
	newCompressionWriter   func(io.WriteCloser, int) io.WriteCloser

	// Read fields
	reader  io.ReadCloser // the current reader returned to the application
	readErr error
	br      *bufio.Reader
	// bytes remaining in current frame.
	// set setReadRemaining to safely update this value and prevent overflow
	readRemaining int64
	readFinal     bool  // true the current message has more frames.
	readLength    int64 // Message size.
	readLimit     int64 // Maximum message size.
	readMaskPos   int
	readMaskKey   [4]byte
	handlePong    func(string) error
	handlePing    func(string) error
	handleClose   func(int, string) error
	readErrCount  int
	messageReader *messageReader // the current low-level reader

	readDecompress         bool // whether last read frame had RSV1 set
	newDecompressionReader func(io.Reader) io.ReadCloser
}

func newConn(conn net.Conn, isServer bool, readBufferSize, writeBufferSize int, writeBufferPool BufferPool, br *bufio.Reader, writeBuf []byte) *Conn {

	if br == nil {
		if readBufferSize == 0 {
			readBufferSize = defaultReadBufferSize
		} else if readBufferSize < maxControlFramePayloadSize {
			// must be large enough for control frame
			readBufferSize = maxControlFramePayloadSize
		}
		br = bufio.NewReaderSize(conn, readBufferSize)
	}

	if writeBufferSize <= 0 {
		writeBufferSize = defaultWriteBufferSize
	}
	writeBufferSize += maxFrameHeaderSize

	if writeBuf == nil && writeBufferPool == nil {
		writeBuf = make([]byte, writeBufferSize)
	}

	mu := make(chan struct{}, 1)
	mu <- struct{}{}
	c := &Conn{
		isServer:               isServer,
		br:                     br,
		conn:                   conn,
		mu:                     mu,
		readFinal:              true,
		writeBuf:               writeBuf,
		writePool:              writeBufferPool,
		writeBufSize:           writeBufferSize,
		enableWriteCompression: true,
		compressionLevel:       defaultCompressionLevel,
	}
	c.SetCloseHandler(nil)
	c.SetPingHandler(nil)
	c.SetPongHandler(nil)
	return c
}

// setReadRemaining tracks the number of bytes remaining on the connection. If n
// overflows, an ErrReadLimit is returned.
func (c *Conn) setReadRemaining(n int64) error {
	if n < 0 {
		return ErrReadLimit
	}

	c.readRemaining = n
	return nil
}

// Subprotocol returns the negotiated protocol for the connection.
func (c *Conn) Subprotocol() string {
	return c.subprotocol
}

// Close closes the underlying network connection without sending or waiting
// for a close message.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// Write methods

func (c *Conn) writeFatal(err error) error {
	c.writeErrMu.Lock()
	if c.writeErr == nil {
		c.writeErr = err
	}
	c.writeErrMu.Unlock()
	return err
}

func (c *Conn) read(n int) ([]byte, error) {
	p, err := c.br.Peek(n)
	if err == io.EOF {
		err = errUnexpectedEOF
	}
	// Discard is guaranteed to succeed because the number of bytes to discard
	// is less than or equal to the number of bytes buffered.
	_, _ = c.br.Discard(len(p))
	return p, err
}

func (c *Conn) write(frameType int, deadline time.Time, buf0, buf1 []byte) error {
	<-c.mu
	defer func() { c.mu <- struct{}{} }()

	c.writeErrMu.Lock()
	err := c.writeErr
	c.writeErrMu.Unlock()
	if err != nil {
		return err
	}

	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return c.writeFatal(err)
	}
	if len(buf1) == 0 {
		_, err = c.conn.Write(buf0)
	} else {
		err = c.writeBufs(buf0, buf1)
	}
	if err != nil {
		return c.writeFatal(err)
	}
	if frameType == CloseMessage {
		_ = c.writeFatal(ErrCloseSent)
	}
	return nil
}

func (c *Conn) writeBufs(bufs ...[]byte) error {
	b := net.Buffers(bufs)
	_, err := b.WriteTo(c.conn)
	return err
}

// WriteControl writes a control message with the given deadline. The allowed
// message types are CloseMessage, PingMessage and PongMessage.
func (c *Conn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	if !isControl(messageType) {
		return errBadWriteOpCode
	}
	if len(data) > maxControlFramePayloadSize {
		return errInvalidControlFrame
	}

	b0 := byte(messageType) | finalBit
	b1 := byte(len(data))
	if !c.isServer {
		b1 |= maskBit
	}

	buf := make([]byte, 0, maxFrameHeaderSize+maxControlFramePayloadSize)
	buf = append(buf, b0, b1)

	if c.isServer {
		buf = append(buf, data...)
	} else {
		key := newMaskKey()
		buf = append(buf, key[:]...)
		buf = append(buf, data...)
		maskBytes(key, 0, buf[6:])
	}

	if deadline.IsZero() {
		// No timeout for zero time.
		<-c.mu
	} else {
		d := time.Until(deadline)
		if d < 0 {
			return errWriteTimeout
		}
		select {
		case <-c.mu:
		default:
			timer := time.NewTimer(d)
			select {
			case <-c.mu:
				timer.Stop()
			case <-timer.C:
				return errWriteTimeout
			}
		}
	}

	defer func() { c.mu <- struct{}{} }()

	c.writeErrMu.Lock()
	err := c.writeErr
	c.writeErrMu.Unlock()
	if err != nil {
		return err
	}

	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return c.writeFatal(err)
	}
	if _, err = c.conn.Write(buf); err != nil {
		return c.writeFatal(err)
	}
	if messageType == CloseMessage {
		_ = c.writeFatal(ErrCloseSent)
	}
	return err
}

// beginMessage prepares a connection and message writer for a new message.
func (c *Conn) beginMessage(mw *messageWriter, messageType int) error {
	// Close previous writer if not already closed by the application. It's
	// probably better to return an error in this situation, but we cannot
	// change this without breaking existing applications.
	if c.writer != nil {
		c.writer.Close()
		c.writer = nil
	}

	if !isControl(messageType) && !isData(messageType) {
		return errBadWriteOpCode
	}

	c.writeErrMu.Lock()
	err := c.writeErr
	c.writeErrMu.Unlock()
	if err != nil {
		return err
	}

	mw.c = c
	mw.frameType = messageType
	mw.pos = maxFrameHeaderSize

	if c.writeBuf == nil {
		wpd, ok := c.writePool.Get().(writePoolData)
		if ok {
			c.writeBuf = wpd.buf
		} else {
			c.writeBuf = make([]byte, c.writeBufSize)
		}
	}
	return nil
}

// NextWriter returns a writer for the next message to send. The writer's Close
// method flushes the complete message to the network.
//
// There can be at most one open writer on a connection. NextWriter closes the
// previous writer if the application has not already done so.
//
// All message types (TextMessage, BinaryMessage, CloseMessage, PingMessage and
// PongMessage) are supported.
func (c *Conn) NextWriter(messageType int) (io.WriteCloser, error) {
	var mw messageWriter
	if err := c.beginMessage(&mw, messageType); err != nil {
		return nil, err
	}
	c.writer = &mw
	if c.newCompressionWriter != nil && c.enableWriteCompression && isData(messageType) {
		w := c.newCompressionWriter(c.writer, c.compressionLevel)
		mw.compress = true
		c.writer = w
	}
	return c.writer, nil
}

type messageWriter struct {
	c         *Conn
	compress  bool // whether next call to flushFrame should set RSV1
	pos       int  // end of data in writeBuf.
	frameType int  // type of the current frame.
	err       error
}

func (w *messageWriter) endMessage(err error) error {
	if w.err != nil {
		return err
	}
	c := w.c
	w.err = err
	c.writer = nil
	if c.writePool != nil {
		c.writePool.Put(writePoolData{buf: c.writeBuf})
		c.writeBuf = nil
	}
	return err
}

// flushFrame writes buffered data and extra as a frame to the network. The
// final argument indicates that this is the last frame in the message.
func (w *messageWriter) flushFrame(final bool, extra []byte) error {
	c := w.c
	length := w.pos - maxFrameHeaderSize + len(extra)

	// Check for invalid control frames.
	if isControl(w.frameType) &&
		(!final || length > maxControlFramePayloadSize) {
		return w.endMessage(errInvalidControlFrame)
	}

	b0 := byte(w.frameType)
	if final {
		b0 |= finalBit
	}
	if w.compress {
		b0 |= rsv1Bit
	}
	w.compress = false

	b1 := byte(0)
	if !c.isServer {
		b1 |= maskBit
	}

	// Assume that the frame starts at beginning of c.writeBuf.
	framePos := 0
	if c.isServer {
		// Adjust up if mask not included in the header.
		framePos = 4
	}

	switch {
	case length >= 65536:
		c.writeBuf[framePos] = b0
		c.writeBuf[framePos+1] = b1 | 127
		binary.BigEndian.PutUint64(c.writeBuf[framePos+2:], uint64(length))
	case length > 125:
		framePos += 6
		c.writeBuf[framePos] = b0
		c.writeBuf[framePos+1] = b1 | 126
		binary.BigEndian.PutUint16(c.writeBuf[framePos+2:], uint16(length))
	default:
		framePos += 8
		c.writeBuf[framePos] = b0
		c.writeBuf[framePos+1] = b1 | byte(length)
	}

	if !c.isServer {
		key := newMaskKey()
		copy(c.writeBuf[maxFrameHeaderSize-4:], key[:])
		maskBytes(key, 0, c.writeBuf[maxFrameHeaderSize:w.pos])
		if len(extra) > 0 {
			return w.endMessage(c.writeFatal(errors.New("websocket: internal error, extra used in client mode")))
		}
	}

	// Write the buffers to the connection with best-effort detection of
	// concurrent writes. See the concurrency section in the package
	// documentation for more info.

	if c.isWriting {
		panic("concurrent write to websocket connection")
	}
	c.isWriting = true

	err := c.write(w.frameType, c.writeDeadline, c.writeBuf[framePos:w.pos], extra)

	if !c.isWriting {
		panic("concurrent write to websocket connection")
	}
	c.isWriting = false

	if err != nil {
		return w.endMessage(err)
	}

	if final {
		_ = w.endMessage(errWriteClosed)
		return nil
	}

	// Setup for next frame.
	w.pos = maxFrameHeaderSize
	w.frameType = continuationFrame
	return nil
}

func (w *messageWriter) ncopy(max int) (int, error) {
	n := len(w.c.writeBuf) - w.pos
	if n <= 0 {
		if err := w.flushFrame(false, nil); err != nil {
			return 0, err
		}
		n = len(w.c.writeBuf) - w.pos
	}
	if n > max {
		n = max
	}
	return n, nil
}

func (w *messageWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	if len(p) > 2*len(w.c.writeBuf) && w.c.isServer {
		// Don't buffer large messages.
		err := w.flushFrame(false, p)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}

	nn := len(p)
	for len(p) > 0 {
		n, err := w.ncopy(len(p))
		if err != nil {
			return 0, err
		}
		copy(w.c.writeBuf[w.pos:], p[:n])
		w.pos += n
		p = p[n:]
	}
	return nn, nil
}

func (w *messageWriter) WriteString(p string) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	nn := len(p)
	for len(p) > 0 {
		n, err := w.ncopy(len(p))
		if err != nil {
			return 0, err
		}
		copy(w.c.writeBuf[w.pos:], p[:n])
		w.pos += n
		p = p[n:]
	}
	return nn, nil
}

func (w *messageWriter) ReadFrom(r io.Reader) (nn int64, err error) {
	if w.err != nil {
		return 0, w.err
	}
	for {
		if w.pos == len(w.c.writeBuf) {
			err = w.flushFrame(false, nil)
			if err != nil {
				break
			}
		}
		var n int
		n, err = r.Read(w.c.writeBuf[w.pos:])
		w.pos += n
		nn += int64(n)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
	}
	return nn, err
}

func (w *messageWriter) Close() error {
	if w.err != nil {
		return w.err
	}
	return w.flushFrame(true, nil)
}

// WritePreparedMessage writes prepared message into connection.
func (c *Conn) WritePreparedMessage(pm *PreparedMessage) error {
	frameType, frameData, err := pm.frame(prepareKey{
		isServer:         c.isServer,
		compress:         c.newCompressionWriter != nil && c.enableWriteCompression && isData(pm.messageType),
		compressionLevel: c.compressionLevel,
	})
	if err != nil {
		return err
	}
	if c.isWriting {
		panic("concurrent write to websocket connection")
	}
	c.isWriting = true
	err = c.write(frameType, c.writeDeadline, frameData, nil)
	if !c.isWriting {
		panic("concurrent write to websocket connection")
	}
	c.isWriting = false
	return err
}

// WriteMessage is a helper method for getting a writer using NextWriter,
// writing the message and closing the writer.
func (c *Conn) WriteMessage(messageType int, data []byte) error {

	if c.isServer && (c.newCompressionWriter == nil || !c.enableWriteCompression) {
		// Fast path with no allocations and single frame.

		var mw messageWriter
		if err := c.beginMessage(&mw, messageType); err != nil {
			return err
		}
		n := copy(c.writeBuf[mw.pos:], data)
		mw.pos += n
		data = data[n:]
		return mw.flushFrame(true, data)
	}

	w, err := c.NextWriter(messageType)
	if err != nil {
		return err
	}
	if _, err = w.Write(data); err != nil {
		return err
	}
	return w.Close()
}

// SetWriteDeadline sets the write deadline on the underlying network
// connection. After a write has timed out, the websocket state is corrupt and
// all future writes will return an error. A zero value for t means writes will
// not time out.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

// Read methods

func (c *Conn) advanceFrame() (int, error) {
	// 1. Skip remainder of previous frame.

	if c.readRemaining > 0 {
		if _, err := io.CopyN(io.Discard, c.br, c.readRemaining); err != nil {
			return noFrame, err
		}
	}

	// 2. Read and parse first two bytes of frame header.
	// To aid debugging, collect and report all errors in the first two bytes
	// of the header.

	var errors []string

	p, err := c.read(2)
	if err != nil {
		return noFrame, err
	}

	frameType := int(p[0] & 0xf)
	final := p[0]&finalBit != 0
	rsv1 := p[0]&rsv1Bit != 0
	rsv2 := p[0]&rsv2Bit != 0
	rsv3 := p[0]&rsv3Bit != 0
	mask := p[1]&maskBit != 0
	_ = c.setReadRemaining(int64(p[1] & 0x7f)) // will not fail because argument is >= 0

	c.readDecompress = false
	if rsv1 {
		if c.newDecompressionReader != nil {
			c.readDecompress = true
		} else {
			errors = append(errors, "RSV1 set")
		}
	}

	if rsv2 {
		errors = append(errors, "RSV2 set")
	}

	if rsv3 {
		errors = append(errors, "RSV3 set")
	}

	switch frameType {
	case CloseMessage, PingMessage, PongMessage:
		if c.readRemaining > maxControlFramePayloadSize {
			errors = append(errors, "len > 125 for control")
		}
		if !final {
			errors = append(errors, "FIN not set on control")
		}
	case TextMessage, BinaryMessage:
		if !c.readFinal {
			errors = append(errors, "data before FIN")
		}
		c.readFinal = final
	case continuationFrame:
		if c.readFinal {
			errors = append(errors, "continuation after FIN")
		}
		c.readFinal = final
	default:
		errors = append(errors, "bad opcode "+strconv.Itoa(frameType))
	}

	if mask != c.isServer {
		errors = append(errors, "bad MASK")
	}

	if len(errors) > 0 {
		return noFrame, c.handleProtocolError(strings.Join(errors, ", "))
	}

	// 3. Read and parse frame length as per
	// https://tools.ietf.org/html/rfc6455#section-5.2
	//
	// The length of the "Payload data", in bytes: if 0-125, that is the payload
	// length.
	// - If 126, the following 2 bytes interpreted as a 16-bit unsigned
	// integer are the payload length.
	// - If 127, the following 8 bytes interpreted as
	// a 64-bit unsigned integer (the most significant bit MUST be 0) are the
	// payload length. Multibyte length quantities are expressed in network byte
	// order.

	switch c.readRemaining {
	case 126:
		p, err := c.read(2)
		if err != nil {
			return noFrame, err
		}

		if err := c.setReadRemaining(int64(binary.BigEndian.Uint16(p))); err != nil {
			return noFrame, err
		}
	case 127:
		p, err := c.read(8)
		if err != nil {
			return noFrame, err
		}

		if err := c.setReadRemaining(int64(binary.BigEndian.Uint64(p))); err != nil {
			return noFrame, err
		}
	}

	// 4. Handle frame masking.

	if mask {
		c.readMaskPos = 0
		p, err := c.read(len(c.readMaskKey))
		if err != nil {
			return noFrame, err
		}
		copy(c.readMaskKey[:], p)
	}

	// 5. For text and binary messages, enforce read limit and return.

	if frameType == continuationFrame || frameType == TextMessage || frameType == BinaryMessage {

		c.readLength += c.readRemaining
		// Don't allow readLength to overflow in the presence of a large readRemaining
		// counter.
		if c.readLength < 0 {
			return noFrame, ErrReadLimit
		}

		if c.readLimit > 0 && c.readLength > c.readLimit {
			// Make a best effort to send a close message describing the problem.
			_ = c.WriteControl(CloseMessage, FormatCloseMessage(CloseMessageTooBig, ""), time.Now().Add(writeWait))
			return noFrame, ErrReadLimit
		}

		return frameType, nil
	}

	// 6. Read control frame payload.

	var payload []byte
	if c.readRemaining > 0 {
		payload, err = c.read(int(c.readRemaining))
		_ = c.setReadRemaining(0) // will not fail because argument is >= 0
		if err != nil {
			return noFrame, err
		}
		if c.isServer {
			maskBytes(c.readMaskKey, 0, payload)
		}
	}

	// 7. Process control frame payload.

	switch frameType {
	case PongMessage:
		if err := c.handlePong(string(payload)); err != nil {
			return noFrame, err
		}
	case PingMessage:
		if err := c.handlePing(string(payload)); err != nil {
			return noFrame, err
		}
	case CloseMessage:
		closeCode := CloseNoStatusReceived
		closeText := ""
		if len(payload) >= 2 {
			closeCode = int(binary.BigEndian.Uint16(payload))
			if !isValidReceivedCloseCode(closeCode) {
				return noFrame, c.handleProtocolError("bad close code " + strconv.Itoa(closeCode))
			}
			closeText = string(payload[2:])
			if !utf8.ValidString(closeText) {
				return noFrame, c.handleProtocolError("invalid utf8 payload in close frame")
			}
		}
		if err := c.handleClose(closeCode, closeText); err != nil {
			return noFrame, err
		}
		return noFrame, &CloseError{Code: closeCode, Text: closeText}
	}

	return frameType, nil
}

func (c *Conn) handleProtocolError(message string) error {
	data := FormatCloseMessage(CloseProtocolError, message)
	if len(data) > maxControlFramePayloadSize {
		data = data[:maxControlFramePayloadSize]
	}
	// Make a best effor to send a close message describing the problem.
	_ = c.WriteControl(CloseMessage, data, time.Now().Add(writeWait))
	return errors.New("websocket: " + message)
}

// NextReader returns the next data message received from the peer. The
// returned messageType is either TextMessage or BinaryMessage.
//
// There can be at most one open reader on a connection. NextReader discards
// the previous message if the application has not already consumed it.
//
// Applications must break out of the application's read loop when this method
// returns a non-nil error value. Errors returned from this method are
// permanent. Once this method returns a non-nil error, all subsequent calls to
// this method return the same error.
func (c *Conn) NextReader() (messageType int, r io.Reader, err error) {
	// Close previous reader, only relevant for decompression.
	if c.reader != nil {
		c.reader.Close()
		c.reader = nil
	}

	c.messageReader = nil
	c.readLength = 0

	for c.readErr == nil {
		frameType, err := c.advanceFrame()
		if err != nil {
			c.readErr = err
			break
		}

		if frameType == TextMessage || frameType == BinaryMessage {
			c.messageReader = &messageReader{c}
			c.reader = c.messageReader
			if c.readDecompress {
				c.reader = c.newDecompressionReader(c.reader)
			}
			return frameType, c.reader, nil
		}
	}

	// Applications that do handle the error returned from this method spin in
	// tight loop on connection failure. To help application developers detect
	// this error, panic on repeated reads to the failed connection.
	c.readErrCount++
	if c.readErrCount >= 1000 {
		panic("repeated read on failed websocket connection")
	}

	return noFrame, nil, c.readErr
}

type messageReader struct{ c *Conn }

func (r *messageReader) Read(b []byte) (int, error) {
	c := r.c
	if c.messageReader != r {
		return 0, io.EOF
	}

	for c.readErr == nil {

		if c.readRemaining > 0 {
			if int64(len(b)) > c.readRemaining {
				b = b[:c.readRemaining]
			}
			n, err := c.br.Read(b)
			c.readErr = err
			if c.isServer {
				c.readMaskPos = maskBytes(c.readMaskKey, c.readMaskPos, b[:n])
			}
			rem := c.readRemaining
			rem -= int64(n)
			_ = c.setReadRemaining(rem) // rem is guaranteed to be >= 0
			if c.readRemaining > 0 && c.readErr == io.EOF {
				c.readErr = errUnexpectedEOF
			}
			return n, c.readErr
		}

		if c.readFinal {
			c.messageReader = nil
			return 0, io.EOF
		}

		frameType, err := c.advanceFrame()
		switch {
		case err != nil:
			c.readErr = err
		case frameType == TextMessage || frameType == BinaryMessage:
			c.readErr = errors.New("websocket: internal error, unexpected text or binary in Reader")
		}
	}

	err := c.readErr
	if err == io.EOF && c.messageReader == r {
		err = errUnexpectedEOF
	}
	return 0, err
}

func (r *messageReader) Close() error {
	return nil
}

// ReadMessage is a helper method for getting a reader using NextReader and
// reading from that reader to a buffer.
func (c *Conn) ReadMessage() (messageType int, p []byte, err error) {
	var r io.Reader
	messageType, r, err = c.NextReader()
	if err != nil {
		return messageType, nil, err
	}
	p, err = io.ReadAll(r)
	return messageType, p, err
}

// SetReadDeadline sets the read deadline on the underlying network connection.
// After a read has timed out, the websocket connection state is corrupt and
// all future reads will return an error. A zero value for t means reads will
// not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetReadLimit sets the maximum size in bytes for a message read from the peer. If a
// message exceeds the limit, the connection sends a close message to the peer
// and returns ErrReadLimit to the application.
func (c *Conn) SetReadLimit(limit int64) {
	c.readLimit = limit
}

// CloseHandler returns the current close handler
func (c *Conn) CloseHandler() func(code int, text string) error {
	return c.handleClose
}

// SetCloseHandler sets the handler for close messages received from the peer.
// The code argument to h is the received close code or CloseNoStatusReceived
// if the close message is empty. The default close handler sends a close
// message back to the peer.
//
// The handler function is called from the NextReader, ReadMessage and message
// reader Read methods. The application must read the connection to process
// close messages as described in the section on Control Messages above.
//
// The connection read methods return a CloseError when a close message is
// received. Most applications should handle close messages as part of their
// normal error handling. Applications should only set a close handler when the
// application must perform some action before sending a close message back to
// the peer.
func (c *Conn) SetCloseHandler(h func(code int, text string) error) {
	if h == nil {
		h = func(code int, text string) error {
			message := FormatCloseMessage(code, "")
			// Make a best effor to send the close message.
			_ = c.WriteControl(CloseMessage, message, time.Now().Add(writeWait))
			return nil
		}
	}
	c.handleClose = h
}

// PingHandler returns the current ping handler
func (c *Conn) PingHandler() func(appData string) error {
	return c.handlePing
}

// SetPingHandler sets the handler for ping messages received from the peer.
// The appData argument to h is the PING message application data. The default
// ping handler sends a pong to the peer.
//
// The handler function is called from the NextReader, ReadMessage and message
// reader Read methods. The application must read the connection to process
// ping messages as described in the section on Control Messages above.
func (c *Conn) SetPingHandler(h func(appData string) error) {
	if h == nil {
		h = func(message string) error {
			// Make a best effort to send the pong message.
			_ = c.WriteControl(PongMessage, []byte(message), time.Now().Add(writeWait))
			return nil
		}
	}
	c.handlePing = h
}

// PongHandler returns the current pong handler
func (c *Conn) PongHandler() func(appData string) error {
	return c.handlePong
}

// SetPongHandler sets the handler for pong messages received from the peer.
// The appData argument to h is the PONG message application data. The default
// pong handler does nothing.
//
// The handler function is called from the NextReader, ReadMessage and message
// reader Read methods. The application must read the connection to process
// pong messages as described in the section on Control Messages above.
func (c *Conn) SetPongHandler(h func(appData string) error) {
	if h == nil {
		h = func(string) error { return nil }
	}
	c.handlePong = h
}

// NetConn returns the underlying connection that is wrapped by c.
// Note that writing to or reading from this connection directly will corrupt the
// WebSocket connection.
func (c *Conn) NetConn() net.Conn {
	return c.conn
}

// UnderlyingConn returns the internal net.Conn. This can be used to further
// modifications to connection specific flags.
// Deprecated: Use the NetConn method.
func (c *Conn) UnderlyingConn() net.Conn {
	return c.conn
}

// EnableWriteCompression enables and disables write compression of
// subsequent text and binary messages. This function is a noop if
// compression was not negotiated with the peer.
func (c *Conn) EnableWriteCompression(enable bool) {
	c.enableWriteCompression = enable
}

// SetCompressionLevel sets the flate compression level for subsequent text and
// binary messages. This function is a noop if compression was not negotiated
// with the peer. See the compress/flate package for a description of
// compression levels.
func (c *Conn) SetCompressionLevel(level int) error {
	if !isValidCompressionLevel(level) {
		return errors.New("websocket: invalid compression level")
	}
	c.compressionLevel = level
	return nil
}

// FormatCloseMessage formats closeCode and text as a WebSocket close message.
// An empty message is returned for code CloseNoStatusReceived.
func FormatCloseMessage(closeCode int, text string) []byte {
	if closeCode == CloseNoStatusReceived {
		// Return empty message because it's illegal to send
		// CloseNoStatusReceived. Return non-nil value in case application
		// checks for nil.
		return []byte{}
	}
	buf := make([]byte, 2+len(text))
	binary.BigEndian.PutUint16(buf, uint16(closeCode))
	copy(buf[2:], text)
	return buf
}

//----------------------------------------------------------------------------------------------------

// JoinMessages concatenates received messages to create a single io.Reader.
// The string term is appended to each message. The returned reader does not
// support concurrent calls to the Read method.
func JoinMessages(c *Conn, term string) io.Reader {
	return &joinReader{c: c, term: term}
}

type joinReader struct {
	c    *Conn
	term string
	r    io.Reader
}

func (r *joinReader) Read(p []byte) (int, error) {
	if r.r == nil {
		var err error
		_, r.r, err = r.c.NextReader()
		if err != nil {
			return 0, err
		}
		if r.term != "" {
			r.r = io.MultiReader(r.r, strings.NewReader(r.term))
		}
	}
	n, err := r.r.Read(p)
	if err == io.EOF {
		err = nil
		r.r = nil
	}
	return n, err
}

//----------------------------------------------------------------------------------------------------

// WriteJSON writes the JSON encoding of v as a message.
//
// Deprecated: Use c.WriteJSON instead.
func WriteJSON(c *Conn, v any) error {
	return c.WriteJSON(v)
}

// WriteJSON writes the JSON encoding of v as a message.
//
// See the documentation for encoding/json Marshal for details about the
// conversion of Go values to JSON.
func (c *Conn) WriteJSON(v any) error {
	w, err := c.NextWriter(TextMessage)
	if err != nil {
		return err
	}
	err1 := json.NewEncoder(w).Encode(v)
	err2 := w.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// ReadJSON reads the next JSON-encoded message from the connection and stores
// it in the value pointed to by v.
//
// Deprecated: Use c.ReadJSON instead.
func ReadJSON(c *Conn, v any) error {
	return c.ReadJSON(v)
}

// ReadJSON reads the next JSON-encoded message from the connection and stores
// it in the value pointed to by v.
//
// See the documentation for the encoding/json Unmarshal function for details
// about the conversion of JSON to a Go value.
func (c *Conn) ReadJSON(v any) error {
	_, r, err := c.NextReader()
	if err != nil {
		return err
	}
	err = json.NewDecoder(r).Decode(v)
	if err == io.EOF {
		// One value is expected in the message.
		err = io.ErrUnexpectedEOF
	}
	return err
}

// ----------------------------------------------------------------------------------------------------
// func maskBytes(key [4]byte, pos int, b []byte) int {
// 	for i := range b {
// 		b[i] ^= key[pos&3]
// 		pos++
// 	}
// 	return pos & 3
// }

//----------------------------------------------------------------------------------------------------

const wordSize = int(unsafe.Sizeof(uintptr(0)))

func maskBytes(key [4]byte, pos int, b []byte) int {
	// Mask one byte at a time for small buffers.
	if len(b) < 2*wordSize {
		for i := range b {
			b[i] ^= key[pos&3]
			pos++
		}
		return pos & 3
	}

	// Mask one byte at a time to word boundary.
	if n := int(uintptr(unsafe.Pointer(&b[0]))) % wordSize; n != 0 {
		n = wordSize - n
		for i := range b[:n] {
			b[i] ^= key[pos&3]
			pos++
		}
		b = b[n:]
	}

	// Create aligned word size key.
	var k [wordSize]byte
	for i := range k {
		k[i] = key[(pos+i)&3]
	}
	kw := *(*uintptr)(unsafe.Pointer(&k))

	// Mask one word at a time.
	n := (len(b) / wordSize) * wordSize
	for i := 0; i < n; i += wordSize {
		*(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(i))) ^= kw
	}

	// Mask one byte at a time for remaining bytes.
	b = b[n:]
	for i := range b {
		b[i] ^= key[pos&3]
		pos++
	}

	return pos & 3
}

//----------------------------------------------------------------------------------------------------

// PreparedMessage caches on the wire representations of a message payload.
// Use PreparedMessage to efficiently send a message payload to multiple
// connections. PreparedMessage is especially useful when compression is used
// because the CPU and memory expensive compression operation can be executed
// once for a given set of compression options.
type PreparedMessage struct {
	messageType int
	data        []byte
	mu          sync.Mutex
	frames      map[prepareKey]*preparedFrame
}

// prepareKey defines a unique set of options to cache prepared frames in PreparedMessage.
type prepareKey struct {
	isServer         bool
	compress         bool
	compressionLevel int
}

// preparedFrame contains data in wire representation.
type preparedFrame struct {
	once sync.Once
	data []byte
}

// NewPreparedMessage returns an initialized PreparedMessage. You can then send
// it to connection using WritePreparedMessage method. Valid wire
// representation will be calculated lazily only once for a set of current
// connection options.
func NewPreparedMessage(messageType int, data []byte) (*PreparedMessage, error) {
	pm := &PreparedMessage{
		messageType: messageType,
		frames:      make(map[prepareKey]*preparedFrame),
		data:        data,
	}

	// Prepare a plain server frame.
	_, frameData, err := pm.frame(prepareKey{isServer: true, compress: false})
	if err != nil {
		return nil, err
	}

	// To protect against caller modifying the data argument, remember the data
	// copied to the plain server frame.
	pm.data = frameData[len(frameData)-len(data):]
	return pm, nil
}

func (pm *PreparedMessage) frame(key prepareKey) (int, []byte, error) {
	pm.mu.Lock()
	frame, ok := pm.frames[key]
	if !ok {
		frame = &preparedFrame{}
		pm.frames[key] = frame
	}
	pm.mu.Unlock()

	var err error
	frame.once.Do(func() {
		// Prepare a frame using a 'fake' connection.
		// TODO: Refactor code in conn.go to allow more direct construction of
		// the frame.
		mu := make(chan struct{}, 1)
		mu <- struct{}{}
		var nc prepareConn
		c := &Conn{
			conn:                   &nc,
			mu:                     mu,
			isServer:               key.isServer,
			compressionLevel:       key.compressionLevel,
			enableWriteCompression: true,
			writeBuf:               make([]byte, defaultWriteBufferSize+maxFrameHeaderSize),
		}
		if key.compress {
			c.newCompressionWriter = compressNoContextTakeover
		}
		err = c.WriteMessage(pm.messageType, pm.data)
		frame.data = nc.buf.Bytes()
	})
	return pm.messageType, frame.data, err
}

type prepareConn struct {
	buf bytes.Buffer
	net.Conn
}

func (pc *prepareConn) Write(p []byte) (int, error)        { return pc.buf.Write(p) }
func (pc *prepareConn) SetWriteDeadline(t time.Time) error { return nil }

//----------------------------------------------------------------------------------------------------

type netDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (fn netDialerFunc) Dial(network, addr string) (net.Conn, error) {
	return fn(context.Background(), network, addr)
}

func (fn netDialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return fn(ctx, network, addr)
}

func proxyFromURL(proxyURL *url.URL, forwardDial netDialerFunc) (netDialerFunc, error) {
	return nil, errors.New("Go-Websocket proxy not supported")
	/*
		if proxyURL.Scheme == "http" {
			return (&httpProxyDialer{proxyURL: proxyURL, forwardDial: forwardDial}).DialContext, nil
		}
		dialer, err := proxy.FromURL(proxyURL, forwardDial)
		if err != nil {
			return nil, err
		}
		if d, ok := dialer.(proxy.ContextDialer); ok {
			return d.DialContext, nil
		}
		return func(ctx context.Context, net, addr string) (net.Conn, error) {
			return dialer.Dial(net, addr)
		}, nil
	*/
}

type httpProxyDialer struct {
	proxyURL    *url.URL
	forwardDial netDialerFunc
}

func (hpd *httpProxyDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	hostPort, _ := hostPortNoPort(hpd.proxyURL)
	conn, err := hpd.forwardDial(ctx, network, hostPort)
	if err != nil {
		return nil, err
	}

	connectHeader := make(http.Header)
	if user := hpd.proxyURL.User; user != nil {
		proxyUser := user.Username()
		if proxyPassword, passwordSet := user.Password(); passwordSet {
			credential := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPassword))
			connectHeader.Set("Proxy-Authorization", "Basic "+credential)
		}
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: connectHeader,
	}

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response. It's OK to use and discard buffered reader here because
	// the remote server does not speak until spoken to.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Close the response body to silence false positives from linters. Reset
	// the buffered reader first to ensure that Close() does not read from
	// conn.
	// Note: Applications must call resp.Body.Close() on a response returned
	// http.ReadResponse to inspect trailers or read another response from the
	// buffered reader. The call to resp.Body.Close() does not release
	// resources.
	br.Reset(bytes.NewReader(nil))
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		f := strings.SplitN(resp.Status, " ", 2)
		return nil, errors.New(f[1])
	}
	return conn, nil
}

//----------------------------------------------------------------------------------------------------

// HandshakeError describes an error with the handshake from the peer.
type HandshakeError struct {
	message string
}

func (e HandshakeError) Error() string { return e.message }

// Upgrader specifies parameters for upgrading an HTTP connection to a
// WebSocket connection.
//
// It is safe to call Upgrader's methods concurrently.
type Upgrader struct {
	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes in bytes. If a buffer
	// size is zero, then buffers allocated by the HTTP server are used. The
	// I/O buffer sizes do not limit the size of the messages that can be sent
	// or received.
	ReadBufferSize, WriteBufferSize int

	// WriteBufferPool is a pool of buffers for write operations. If the value
	// is not set, then write buffers are allocated to the connection for the
	// lifetime of the connection.
	//
	// A pool is most useful when the application has a modest volume of writes
	// across a large number of connections.
	//
	// Applications should use a single pool for each unique value of
	// WriteBufferSize.
	WriteBufferPool BufferPool

	// Subprotocols specifies the server's supported protocols in order of
	// preference. If this field is not nil, then the Upgrade method negotiates a
	// subprotocol by selecting the first match in this list with a protocol
	// requested by the client. If there's no match, then no protocol is
	// negotiated (the Sec-Websocket-Protocol header is not included in the
	// handshake response).
	Subprotocols []string

	// Error specifies the function for generating HTTP error responses. If Error
	// is nil, then http.Error is used to generate the HTTP response.
	Error func(w http.ResponseWriter, r *http.Request, status int, reason error)

	// CheckOrigin returns true if the request Origin header is acceptable. If
	// CheckOrigin is nil, then a safe default is used: return false if the
	// Origin request header is present and the origin host is not equal to
	// request Host header.
	//
	// A CheckOrigin function should carefully validate the request origin to
	// prevent cross-site request forgery.
	CheckOrigin func(r *http.Request) bool

	// EnableCompression specify if the server should attempt to negotiate per
	// message compression (RFC 7692). Setting this value to true does not
	// guarantee that compression will be supported. Currently only "no context
	// takeover" modes are supported.
	EnableCompression bool
}

func (u *Upgrader) returnError(w http.ResponseWriter, r *http.Request, status int, reason string) (*Conn, error) {
	err := HandshakeError{reason}
	if u.Error != nil {
		u.Error(w, r, status, err)
	} else {
		w.Header().Set("Sec-Websocket-Version", "13")
		http.Error(w, http.StatusText(status), status)
	}
	return nil, err
}

// checkSameOrigin returns true if the origin is not set or is equal to the request host.
func checkSameOrigin(r *http.Request) bool {
	origin := r.Header["Origin"]
	if len(origin) == 0 {
		return true
	}
	u, err := url.Parse(origin[0])
	if err != nil {
		return false
	}
	return equalASCIIFold(u.Host, r.Host)
}

func (u *Upgrader) selectSubprotocol(r *http.Request, responseHeader http.Header) string {
	if u.Subprotocols != nil {
		clientProtocols := Subprotocols(r)
		for _, clientProtocol := range clientProtocols {
			for _, serverProtocol := range u.Subprotocols {
				if clientProtocol == serverProtocol {
					return clientProtocol
				}
			}
		}
	} else if responseHeader != nil {
		return responseHeader.Get("Sec-Websocket-Protocol")
	}
	return ""
}

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
//
// The responseHeader is included in the response to the client's upgrade
// request. Use the responseHeader to specify cookies (Set-Cookie). To specify
// subprotocols supported by the server, set Upgrader.Subprotocols directly.
//
// If the upgrade fails, then Upgrade replies to the client with an HTTP error
// response.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error) {
	const badHandshake = "websocket: the client is not using the websocket protocol: "

	if !tokenListContainsValue(r.Header, "Connection", "upgrade") {
		return u.returnError(w, r, http.StatusBadRequest, badHandshake+"'upgrade' token not found in 'Connection' header")
	}

	if !tokenListContainsValue(r.Header, "Upgrade", "websocket") {
		w.Header().Set("Upgrade", "websocket")
		return u.returnError(w, r, http.StatusUpgradeRequired, badHandshake+"'websocket' token not found in 'Upgrade' header")
	}

	if r.Method != http.MethodGet {
		return u.returnError(w, r, http.StatusMethodNotAllowed, badHandshake+"request method is not GET")
	}

	if !tokenListContainsValue(r.Header, "Sec-Websocket-Version", "13") {
		return u.returnError(w, r, http.StatusBadRequest, "websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' header")
	}

	if _, ok := responseHeader["Sec-Websocket-Extensions"]; ok {
		return u.returnError(w, r, http.StatusInternalServerError, "websocket: application specific 'Sec-WebSocket-Extensions' headers are unsupported")
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(r) {
		return u.returnError(w, r, http.StatusForbidden, "websocket: request origin not allowed by Upgrader.CheckOrigin")
	}

	challengeKey := r.Header.Get("Sec-Websocket-Key")
	if !isValidChallengeKey(challengeKey) {
		return u.returnError(w, r, http.StatusBadRequest, "websocket: not a websocket handshake: 'Sec-WebSocket-Key' header must be Base64 encoded value of 16-byte in length")
	}

	subprotocol := u.selectSubprotocol(r, responseHeader)

	// Negotiate PMCE
	var compress bool
	if u.EnableCompression {
		for _, ext := range parseExtensions(r.Header) {
			if ext[""] != "permessage-deflate" {
				continue
			}
			compress = true
			break
		}
	}

	netConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return u.returnError(w, r, http.StatusInternalServerError,
			"websocket: hijack: "+err.Error())
	}

	// Close the network connection when returning an error. The variable
	// netConn is set to nil before the success return at the end of the
	// function.
	defer func() {
		if netConn != nil {
			// It's safe to ignore the error from Close() because this code is
			// only executed when returning a more important error to the
			// application.
			_ = netConn.Close()
		}
	}()

	var br *bufio.Reader
	if u.ReadBufferSize == 0 && brw.Reader.Size() > 256 {
		// Use hijacked buffered reader as the connection reader.
		br = brw.Reader
	} else if brw.Reader.Buffered() > 0 {
		// Wrap the network connection to read buffered data in brw.Reader
		// before reading from the network connection. This should be rare
		// because a client must not send message data before receiving the
		// handshake response.
		netConn = &brNetConn{br: brw.Reader, Conn: netConn}
	}

	buf := brw.Writer.AvailableBuffer()

	var writeBuf []byte
	if u.WriteBufferPool == nil && u.WriteBufferSize == 0 && len(buf) >= maxFrameHeaderSize+256 {
		// Reuse hijacked write buffer as connection buffer.
		writeBuf = buf
	}

	c := newConn(netConn, true, u.ReadBufferSize, u.WriteBufferSize, u.WriteBufferPool, br, writeBuf)
	c.subprotocol = subprotocol

	if compress {
		c.newCompressionWriter = compressNoContextTakeover
		c.newDecompressionReader = decompressNoContextTakeover
	}

	// Use larger of hijacked buffer and connection write buffer for header.
	p := buf
	if len(c.writeBuf) > len(p) {
		p = c.writeBuf
	}
	p = p[:0]

	p = append(p, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "...)
	p = append(p, computeAcceptKey(challengeKey)...)
	p = append(p, "\r\n"...)
	if c.subprotocol != "" {
		p = append(p, "Sec-WebSocket-Protocol: "...)
		p = append(p, c.subprotocol...)
		p = append(p, "\r\n"...)
	}
	if compress {
		p = append(p, "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"...)
	}
	for k, vs := range responseHeader {
		if k == "Sec-Websocket-Protocol" {
			continue
		}
		for _, v := range vs {
			p = append(p, k...)
			p = append(p, ": "...)
			for i := 0; i < len(v); i++ {
				b := v[i]
				if b <= 31 {
					// prevent response splitting.
					b = ' '
				}
				p = append(p, b)
			}
			p = append(p, "\r\n"...)
		}
	}
	p = append(p, "\r\n"...)

	if u.HandshakeTimeout > 0 {
		if err := netConn.SetWriteDeadline(time.Now().Add(u.HandshakeTimeout)); err != nil {
			return nil, err
		}
	} else {
		// Clear deadlines set by HTTP server.
		if err := netConn.SetDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}

	if _, err = netConn.Write(p); err != nil {
		return nil, err
	}
	if u.HandshakeTimeout > 0 {
		if err := netConn.SetWriteDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}

	// Success! Set netConn to nil to stop the deferred function above from
	// closing the network connection.
	netConn = nil

	return c, nil
}

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
//
// Deprecated: Use websocket.Upgrader instead.
//
// Upgrade does not perform origin checking. The application is responsible for
// checking the Origin header before calling Upgrade. An example implementation
// of the same origin policy check is:
//
//	if req.Header.Get("Origin") != "http://"+req.Host {
//		http.Error(w, "Origin not allowed", http.StatusForbidden)
//		return
//	}
//
// If the endpoint supports subprotocols, then the application is responsible
// for negotiating the protocol used on the connection. Use the Subprotocols()
// function to get the subprotocols requested by the client. Use the
// Sec-Websocket-Protocol response header to specify the subprotocol selected
// by the application.
//
// The responseHeader is included in the response to the client's upgrade
// request. Use the responseHeader to specify cookies (Set-Cookie) and the
// negotiated subprotocol (Sec-Websocket-Protocol).
//
// The connection buffers IO to the underlying network connection. The
// readBufSize and writeBufSize parameters specify the size of the buffers to
// use. Messages can be larger than the buffers.
//
// If the request is not a valid WebSocket handshake, then Upgrade returns an
// error of type HandshakeError. Applications should handle this error by
// replying to the client with an HTTP error response.
func Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header, readBufSize, writeBufSize int) (*Conn, error) {
	u := Upgrader{ReadBufferSize: readBufSize, WriteBufferSize: writeBufSize}
	u.Error = func(w http.ResponseWriter, r *http.Request, status int, reason error) {
		// don't return errors to maintain backwards compatibility
	}
	u.CheckOrigin = func(r *http.Request) bool {
		// allow all connections by default
		return true
	}
	return u.Upgrade(w, r, responseHeader)
}

// Subprotocols returns the subprotocols requested by the client in the
// Sec-Websocket-Protocol header.
func Subprotocols(r *http.Request) []string {
	h := strings.TrimSpace(r.Header.Get("Sec-Websocket-Protocol"))
	if h == "" {
		return nil
	}
	protocols := strings.Split(h, ",")
	for i := range protocols {
		protocols[i] = strings.TrimSpace(protocols[i])
	}
	return protocols
}

// IsWebSocketUpgrade returns true if the client requested upgrade to the
// WebSocket protocol.
func IsWebSocketUpgrade(r *http.Request) bool {
	return tokenListContainsValue(r.Header, "Connection", "upgrade") &&
		tokenListContainsValue(r.Header, "Upgrade", "websocket")
}

type brNetConn struct {
	br *bufio.Reader
	net.Conn
}

func (b *brNetConn) Read(p []byte) (n int, err error) {
	if b.br != nil {
		// Limit read to buferred data.
		if n := b.br.Buffered(); len(p) > n {
			p = p[:n]
		}
		n, err = b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.Conn.Read(p)
}

// NetConn returns the underlying connection that is wrapped by b.
func (b *brNetConn) NetConn() net.Conn {
	return b.Conn
}

//----------------------------------------------------------------------------------------------------

var keyGUID = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

func computeAcceptKey(challengeKey string) string {
	h := sha1.New()
	h.Write([]byte(challengeKey))
	h.Write(keyGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func generateChallengeKey() (string, error) {
	p := make([]byte, 16)
	if _, err := io.ReadFull(cryptorand.Reader, p); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

// Token octets per RFC 2616.
var isTokenOctet = [256]bool{
	'!':  true,
	'#':  true,
	'$':  true,
	'%':  true,
	'&':  true,
	'\'': true,
	'*':  true,
	'+':  true,
	'-':  true,
	'.':  true,
	'0':  true,
	'1':  true,
	'2':  true,
	'3':  true,
	'4':  true,
	'5':  true,
	'6':  true,
	'7':  true,
	'8':  true,
	'9':  true,
	'A':  true,
	'B':  true,
	'C':  true,
	'D':  true,
	'E':  true,
	'F':  true,
	'G':  true,
	'H':  true,
	'I':  true,
	'J':  true,
	'K':  true,
	'L':  true,
	'M':  true,
	'N':  true,
	'O':  true,
	'P':  true,
	'Q':  true,
	'R':  true,
	'S':  true,
	'T':  true,
	'U':  true,
	'W':  true,
	'V':  true,
	'X':  true,
	'Y':  true,
	'Z':  true,
	'^':  true,
	'_':  true,
	'`':  true,
	'a':  true,
	'b':  true,
	'c':  true,
	'd':  true,
	'e':  true,
	'f':  true,
	'g':  true,
	'h':  true,
	'i':  true,
	'j':  true,
	'k':  true,
	'l':  true,
	'm':  true,
	'n':  true,
	'o':  true,
	'p':  true,
	'q':  true,
	'r':  true,
	's':  true,
	't':  true,
	'u':  true,
	'v':  true,
	'w':  true,
	'x':  true,
	'y':  true,
	'z':  true,
	'|':  true,
	'~':  true,
}

// skipSpace returns a slice of the string s with all leading RFC 2616 linear
// whitespace removed.
func skipSpace(s string) (rest string) {
	i := 0
	for ; i < len(s); i++ {
		if b := s[i]; b != ' ' && b != '\t' {
			break
		}
	}
	return s[i:]
}

// nextToken returns the leading RFC 2616 token of s and the string following
// the token.
func nextToken(s string) (token, rest string) {
	i := 0
	for ; i < len(s); i++ {
		if !isTokenOctet[s[i]] {
			break
		}
	}
	return s[:i], s[i:]
}

// nextTokenOrQuoted returns the leading token or quoted string per RFC 2616
// and the string following the token or quoted string.
func nextTokenOrQuoted(s string) (value string, rest string) {
	if !strings.HasPrefix(s, "\"") {
		return nextToken(s)
	}
	s = s[1:]
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[:i], s[i+1:]
		case '\\':
			p := make([]byte, len(s)-1)
			j := copy(p, s[:i])
			escape := true
			for i = i + 1; i < len(s); i++ {
				b := s[i]
				switch {
				case escape:
					escape = false
					p[j] = b
					j++
				case b == '\\':
					escape = true
				case b == '"':
					return string(p[:j]), s[i+1:]
				default:
					p[j] = b
					j++
				}
			}
			return "", ""
		}
	}
	return "", ""
}

// equalASCIIFold returns true if s is equal to t with ASCII case folding as
// defined in RFC 4790.
func equalASCIIFold(s, t string) bool {
	for s != "" && t != "" {
		sr, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		tr, size := utf8.DecodeRuneInString(t)
		t = t[size:]
		if sr == tr {
			continue
		}
		if 'A' <= sr && sr <= 'Z' {
			sr = sr + 'a' - 'A'
		}
		if 'A' <= tr && tr <= 'Z' {
			tr = tr + 'a' - 'A'
		}
		if sr != tr {
			return false
		}
	}
	return s == t
}

// tokenListContainsValue returns true if the 1#token header with the given
// name contains a token equal to value with ASCII case folding.
func tokenListContainsValue(header http.Header, name string, value string) bool {
headers:
	for _, s := range header[name] {
		for {
			var t string
			t, s = nextToken(skipSpace(s))
			if t == "" {
				continue headers
			}
			s = skipSpace(s)
			if s != "" && s[0] != ',' {
				continue headers
			}
			if equalASCIIFold(t, value) {
				return true
			}
			if s == "" {
				continue headers
			}
			s = s[1:]
		}
	}
	return false
}

// parseExtensions parses WebSocket extensions from a header.
func parseExtensions(header http.Header) []map[string]string {
	// From RFC 6455:
	//
	//  Sec-WebSocket-Extensions = extension-list
	//  extension-list = 1#extension
	//  extension = extension-token *( ";" extension-param )
	//  extension-token = registered-token
	//  registered-token = token
	//  extension-param = token [ "=" (token | quoted-string) ]
	//     ;When using the quoted-string syntax variant, the value
	//     ;after quoted-string unescaping MUST conform to the
	//     ;'token' ABNF.

	var result []map[string]string
headers:
	for _, s := range header["Sec-Websocket-Extensions"] {
		for {
			var t string
			t, s = nextToken(skipSpace(s))
			if t == "" {
				continue headers
			}
			ext := map[string]string{"": t}
			for {
				s = skipSpace(s)
				if !strings.HasPrefix(s, ";") {
					break
				}
				var k string
				k, s = nextToken(skipSpace(s[1:]))
				if k == "" {
					continue headers
				}
				s = skipSpace(s)
				var v string
				if strings.HasPrefix(s, "=") {
					v, s = nextTokenOrQuoted(skipSpace(s[1:]))
					s = skipSpace(s)
				}
				if s != "" && s[0] != ',' && s[0] != ';' {
					continue headers
				}
				ext[k] = v
			}
			if s != "" && s[0] != ',' {
				continue headers
			}
			result = append(result, ext)
			if s == "" {
				continue headers
			}
			s = s[1:]
		}
	}
	return result
}

// isValidChallengeKey checks if the argument meets RFC6455 specification.
func isValidChallengeKey(s string) bool {
	// From RFC6455:
	//
	// A |Sec-WebSocket-Key| header field with a base64-encoded (see
	// Section 4 of [RFC4648]) value that, when decoded, is 16 bytes in
	// length.

	if s == "" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(decoded) == 16
}

//----------------------------------------------------------------------------------------------------
