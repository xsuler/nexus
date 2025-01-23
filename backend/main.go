// main.go
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"fmt"
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
    "expand_description": "一个实时输出时间的html组件",
    "action": "(input, update) => { setInterval(() => update(new Date().toLocaleTimeString()), 1000); }"
}


{
    "name": "二维码生成器",
    "expand_description": "一个专业的二维码生成器,用户输入文本，输出对应的二维码",
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

你生成的render或者action中如果要嵌入外部来源url，使用proxy，例如

<iframe 
                src="/proxy?url=${encodeURIComponent(data.url)}"
                loading="lazy"
                allow="accelerometer; camera; geolocation; microphone; payment; usb"
            ></iframe>
	    
请严格遵循以下规则：
1. JSON字符串中的代码保持单行格式
2. 优先使用jsDelivr的稳定依赖
3. 禁止使用双引号，仅使用单引号
4. render和action代码中不得包含换行符，都是用分号，不能有任何control character
5. 调用update一定要及时，不要过太长时间
6. 禁用以下依赖：marked.min.js, jspdf.umd.min.js, three.js
7. 尽可能不要让用户输入什么，即尽可能不渲染input组件

 你的工作将follow如下步骤
 1. 扩充用户的输入，完善的重新描述它，填写到extend_description 中，尽可能详细扩充，超过500字，发挥你的想象力，尽可能利用各种可视化工具，丰富生成的组件展示内容
 2. 对完善后的重新描述输出json规范
 3. 对于能动态更新的，尽可能应用动态更新手段，动态渲染组件
 
 `


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
		recoveryMiddleware(),
	)

	router.POST("/api/generate", handleGeneration)
	router.GET("/proxy", handleProxy)
	router.GET("/", func(c *gin.Context) {
		c.File("./frontend/index.html")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on :%s\n", port)
	log.Fatal(router.Run(":" + port))
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

	parsedURL, err := url.Parse(decodedURL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL format"})
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

	// Enhanced headers configuration
	req.Header = http.Header{
		"User-Agent":      []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
		"Accept":          []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Accept-Language": []string{"en-US,en;q=0.9"},
		"Referer":         []string{fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)},
		"Origin":          []string{fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)},
		"DNT":             []string{"1"},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Proxy request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to fetch target resource"})
		return
	}
	defer resp.Body.Close()

	// Security header cleanup
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("X-Frame-Options")
	resp.Header.Del("X-Content-Type-Options")

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

	c.Status(resp.StatusCode)
	for k, v := range resp.Header {
		c.Writer.Header()[k] = v
	}
	io.Copy(c.Writer, resp.Body)
}

func isAllowedDomain(rawURL string) bool {
	return true
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
