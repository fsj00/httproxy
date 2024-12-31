package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"io/ioutil"
	"strings"
	"time"
)

// handleHTTPAndHTTPSRequest 处理 HTTP 和 HTTPS 请求，动态获取请求的 URL
func handleHTTPAndHTTPSRequest(w http.ResponseWriter, r *http.Request, echoText string, allEcho bool) {
	// 记录每次请求的接收
	log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	startTime := time.Now()

	// 如果启用了 all-echo，直接返回 echoText
	if allEcho {
		log.Println("all-echo is enabled. Responding with echoText for all requests.")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(echoText))
		log.Printf("Handled all-echo request in %v", time.Since(startTime))
		return
	}

	// 检查请求的路径是否以 "/echo" 结尾
	if strings.HasSuffix(r.URL.Path, "/echo") {
		// 如果是以 /echo 结尾的路径，直接返回 200 OK 和自定义的响应内容
		log.Println("Responding to path ending with /echo with text:", echoText)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(echoText))
		log.Printf("Handled /echo request in %v", time.Since(startTime))
		return
	}

	// 从请求的 URL 获取目标地址
	realServiceURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)

	// 解析真实服务的 URL
	realService, err := url.Parse(realServiceURL)
	if err != nil {
		log.Printf("Invalid real service URL: %v", err)
		http.Error(w, fmt.Sprintf("Invalid real service URL: %v", err), http.StatusBadRequest)
		return
	}

	// 创建一个自定义的 http.Client，禁用证书验证
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 忽略证书验证
			},
		},
	}

	// 创建一个新的 HTTP 请求
	req, err := http.NewRequest(r.Method, realService.String(), r.Body)
	if err != nil {
		log.Printf("Failed to create new request: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create new request: %v", err), http.StatusInternalServerError)
		return
	}

	// 设置请求头，复制原始请求的头信息
	req.Header = r.Header

	// 记录请求的转发
	log.Printf("Forwarding request to: %s %s", realService.String(), r.Method)

	// 通过 http.Client 发起请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 记录响应状态
	log.Printf("Received response: %d from %s", resp.StatusCode, realService.String())

	// 将响应状态码、头部和响应体返回给客户端
	w.WriteHeader(resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		http.Error(w, fmt.Sprintf("Failed to read response body: %v", err), http.StatusInternalServerError)
		return
	}

	// 返回响应内容
	w.Write(body)
	log.Printf("Handled request in %v", time.Since(startTime))
}

// startHTTPServer 启动 HTTP 服务器，默认监听端口 80
func startHTTPServer(listenPort int, echoText string, allEcho bool) {
	// 创建一个新的 ServeMux 路由器
	mux := http.NewServeMux()

	// 设置路由和请求处理函数
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleHTTPAndHTTPSRequest(w, r, echoText, allEcho)
	})

	// 启动 HTTP 服务器
	log.Printf("Starting HTTP server on port %d...", listenPort)
	err := http.ListenAndServe(fmt.Sprintf(":%d", listenPort), mux)
	if err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

// startHTTPSProxy 启动 HTTPS 代理服务器，默认监听端口 443
func startHTTPSProxy(listenPort int, certFile string, keyFile string, echoText string, allEcho bool) {
	// 创建一个新的 ServeMux 路由器
	mux := http.NewServeMux()

	// 设置路由和请求处理函数
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleHTTPAndHTTPSRequest(w, r, echoText, allEcho)
	})

	// 加载自定义的证书和私钥
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load certificate and key: %v", err)
	}

	// 创建 HTTPS 服务器并启动监听
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", listenPort),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
		Handler:   mux,
	}

	// 启动 HTTPS 代理
	log.Printf("Starting HTTPS proxy server on port %d...", listenPort)
	err = server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}

func main() {
	// 定义命令行参数
	listenPortHTTP := flag.Int("http-port", 80, "Port to listen on for HTTP requests")
	listenPortHTTPS := flag.Int("https-port", 443, "Port to listen on for HTTPS requests")
	certFile := flag.String("cert", "cert.pem", "Path to SSL certificate file")
	keyFile := flag.String("key", "key.pem", "Path to SSL private key file")
	echoText := flag.String("text", "hello echo", "Response content for /echo endpoint")
	allEcho := flag.Bool("all-echo", false, "If enabled, all requests will return the echoText")

	// 解析命令行参数
	flag.Parse()

	// 启动 HTTP 服务器
	go startHTTPServer(*listenPortHTTP, *echoText, *allEcho)

	// 启动 HTTPS 代理
	startHTTPSProxy(*listenPortHTTPS, *certFile, *keyFile, *echoText, *allEcho)
}
