// main.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	PROMPT_TEMPLATE = `用户希望实现app，需要渲染一个app页面，请你输出这个app页面的渲染json

### JSON 任务配置极简指南

{
    "name": "实时时钟",
    "action": "(input, update) => { setInterval(() => update(new Date().toLocaleTimeString()), 1000); }"
}

{
    "name": "加密货币价格看板",
    "action": "(input, update) => { 
        update({ type: 'iframe', url: 'https://coinmarketcap.com/' });
        return '正在加载价格看板...';
    }",
    "output": {}
}

{
    "name": "二维码生成器",
    "dependencies": [
        "https://cdn.jsdelivr.net/npm/qrcode-svg@1.1.0/lib/qrcode.min.js"
    ],
    "input": {
        "render": "(container, update) => { 
            const input = document.createElement('input'); 
            input.className = 'input-field'; 
            input.placeholder = '输入内容'; 
            container.appendChild(input); 
        }"
    },
    "output": {
        "render": "(container, data) => {
            container.innerHTML = '';
            if (!data) {
                const err = document.createElement('div');
                err.className = 'error';
                err.textContent = '内容为空';
                container.appendChild(err);
                return;
            }
            try {
                const qr = new QRCode({ content: data, width: 128, height: 128 });
                container.innerHTML = qr.svg();
            } catch(e) {
                const err = document.createElement('div');
                err.className = 'error';
                err.textContent = '生成失败: ' + e.message;
                container.appendChild(err);
            }
        }"
    },
    "action": "(input, update) => { 
        if (typeof input !== 'string' || !input.trim()) return; 
        update(input.trim()); 
    }"
}

请严格遵循以下规则：
1. JSON字符串中的代码保持单行格式
2. 优先使用jsDelivr的稳定依赖
3. 禁止使用双引号，仅使用单引号
4. 代码中不得包含换行符
5. 输出不包含任何按钮元素
6. 禁用以下依赖：marked.min.js, jspdf.umd.min.js, three.js`

	MAX_REQUEST_SIZE   = 1 << 20 // 1MB
	PROXY_TIMEOUT      = 15 * time.Second
	DEFAULT_ALLOWED_DNS = "coinmarketcap.com,coingecko.com,jsdelivr.net,unpkg.com"
)

var (
	allowedDomains []string
	apiSecret      string
)

func init() {
	// 初始化配置
	apiSecret = os.Getenv("DEEPSEEK_API_KEY")
	if apiSecret == "" {
		log.Fatal("DEEPSEEK_API_KEY environment variable is required")
	}

	domainList := os.Getenv("ALLOWED_DOMAINS")
	if domainList == "" {
		domainList = DEFAULT_ALLOWED_DNS
	}
	allowedDomains = strings.Split(domainList, ",")
}

func main() {
	router := gin.Default()

	router.Use(
		securityHeaders(),
		requestLimiter(),
		recoveryMiddleware(),
	)

	router.POST("/api/generate", handleGeneration)
	router.GET("/proxy", handleProxy)
	router.Static("/", "./frontend")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on :%s\n", port)
	log.Fatal(router.Run(":" + port))
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Content-Security-Policy", 
			"default-src 'self'; "+
			"script-src 'self' https: 'unsafe-inline'; "+
			"style-src 'self' https: 'unsafe-inline'; "+
			"img-src 'self' data: https:; "+
			"connect-src 'self' https://api.deepseek.com;")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func requestLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MAX_REQUEST_SIZE)
		c.Next()
	}
}

func recoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Internal server error",
				})
			}
		}()
		c.Next()
	}
}

type GenerateRequest struct {
	Prompt string `json:"prompt" binding:"required"`
}

func handleGeneration(c *gin.Context) {
	start := time.Now()

	var req GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	payload := map[string]interface{}{
		"model": "deepseek-coder",
		"messages": []map[string]string{
			{"role": "system", "content": PROMPT_TEMPLATE},
			{"role": "user", "content": req.Prompt},
		},
		"response_format": map[string]string{"type": "json_object"},
	}

	bodyBytes, _ := json.Marshal(payload)
	proxyReq, _ := http.NewRequest("POST", "https://api.deepseek.com/chat/completions", bytes.NewReader(bodyBytes))
	proxyReq.Header.Set("Content-Type", "application/json")
	proxyReq.Header.Set("Authorization", "Bearer "+apiSecret)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("API request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Upstream service unavailable"})
		return
	}
	defer resp.Body.Close()

	log.Printf("Generation completed in %v", time.Since(start))

	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

func handleProxy(c *gin.Context) {
	targetURL := c.Query("url")
	if targetURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing url parameter"})
		return
	}

	decodedURL, err := url.QueryUnescape(targetURL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL encoding"})
		return
	}

	if !isAllowedDomain(decodedURL) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "Domain not permitted",
			"domain": getHostname(decodedURL),
		})
		return
	}

	client := &http.Client{
		Timeout: PROXY_TIMEOUT,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", decodedURL, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL format"})
		return
	}

	req.Header.Set("User-Agent", "NexusToolkit/1.0 (+https://github.com/nexus-toolkit)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Proxy request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to fetch target resource"})
		return
	}
	defer resp.Body.Close()

	// 清理响应头
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("X-Frame-Options")
	resp.Header.Del("X-Content-Type-Options")

	// 处理HTML内容
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read content"})
			return
		}

		cleaned := sanitizeContent(body)
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), cleaned)
		return
	}

	// 传输非HTML内容
	c.Status(resp.StatusCode)
	for k, v := range resp.Header {
		c.Writer.Header()[k] = v
	}
	io.Copy(c.Writer, resp.Body)
}

func isAllowedDomain(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	hostname := parsed.Hostname()
	for _, domain := range allowedDomains {
		if strings.HasSuffix(hostname, domain) {
			return true
		}
	}
	return false
}

func sanitizeContent(body []byte) []byte {
	// 移除X-Frame-Options meta标签
	metaPattern := regexp.MustCompile(`<meta[^>]+(http-equiv=["']X-Frame-Options['"])[^>]*>`)
	cleaned := metaPattern.ReplaceAll(body, nil)

	// 移除CSP策略
	cspPattern := regexp.MustCompile(`<meta[^>]+(http-equiv=["']Content-Security-Policy['"][^>]*)>`)
	cleaned = cspPattern.ReplaceAll(cleaned, nil)

	// 移除frame检测脚本
	scriptPattern := regexp.MustCompile(`<script[^>]*>([\s\S]*?(top|parent|self)[\s\S]*?)<\/script>`)
	return scriptPattern.ReplaceAll(cleaned, nil)
}

func getHostname(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "invalid_url"
	}
	return parsed.Hostname()
}
