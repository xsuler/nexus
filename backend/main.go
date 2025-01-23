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
	PROMPT_TEMPLATE = `

### 应用页面渲染 JSON 生成指南

用户希望开发一个功能丰富的应用程序，需渲染多个不同功能的页面组件。请根据以下指导，输出完整且结构化的应用页面渲染 JSON。生成的 JSON 应涵盖各个组件的详细描述、依赖项、输入输出处理逻辑，以及动态更新机制，以确保应用程序的交互性和响应性。

#### 主要规则与要求

1. **代码格式**：
    - JSON 字符串中的代码段必须保持单行格式，避免使用换行符。
    - 禁止使用双引号，仅允许使用单引号，以确保 JSON 结构的正确性。
    - 在 code 的代码中，所有逻辑必须用分号隔开，不得包含任何控制字符。

2. **依赖管理**：
    - 优先选择来自 jsDelivr 的稳定依赖库，确保组件的可靠性和加载速度。
    - 禁止使用以下依赖库：marked.min.js、jspdf.umd.min.js、three.js，以避免潜在的兼容性和安全性问题。
    - 若需引用外部资源，请通过代理 URL 进行嵌入，示例如下：

      <iframe 
          src="/proxy?url=${data.url}"
          loading="lazy"
          allow="accelerometer; camera; geolocation; microphone; payment; usb"
      ></iframe>


3. **用户交互**：
    - 尽量减少用户输入需求，避免渲染输入组件，提升用户体验和界面简洁度。
    - 对于需要用户交互的功能，应采用自动化或智能化的处理方式。

4. **动态更新**：
    - 对于能够动态更新的数据和显示内容，必须采用实时更新机制，确保界面内容的及时性和准确性。
    - 使用高效的状态管理和更新方法，避免长时间延迟，确保用户操作的流畅性。

5. **安全与性能**：
    - 所有外部资源的引用均需经过严格的验证和代理，以防止安全漏洞。
    - 组件应优化性能，避免不必要的资源消耗和加载延迟。

#### 生成步骤

1. **扩展与完善描述**：
    - 对用户需求进行详细扩展，填写到 expand_description 字段中。
    - 每个组件的描述应超过 500 字，充分发挥想象力，结合各种可视化工具，丰富组件的展示内容。
    - 描述应涵盖组件的功能、外观、交互方式、响应机制及其在应用中的具体应用场景。

2. **输出 JSON 规范**：
    - 根据扩展后的描述，生成符合规范的 JSON 配置。
    - 每个组件的 JSON 配置应包含以下字段：
        - name：组件名称。
        - expand_description：扩展后的详细描述。
        - deps：所需的外部依赖库，优先使用 jsDelivr 链接。
        - code：输出渲染逻辑。

3. **应用动态更新手段**：
    - 对于能够动态变化的数据，应用实时更新机制。
    - 示例包括但不限于定时刷新、事件驱动更新、数据绑定等方法，以确保组件内容的时效性和交互性。

#### 示例 JSON 配置

以下是1个组件的示例配置，以供参考：


{
  "deps": ["https://cdn.jsdelivr.net/npm/qrcode@1.5.0/build/qrcode.min.js"],
  "code": "const e=document.createElement('input');e.type='text';e.placeholder='输入二维码内容';e.style='width:100%;padding:12px;margin-bottom:20px;border:2px solid #7B61FF;border-radius:8px;background:rgba(0,0,0,0.3);color:white;';const t=document.createElement('canvas');t.style.display='block';t.style.margin='0 auto';t.style.boxShadow='0 4px 12px rgba(0,0,0,0.2)';container.appendChild(e);container.appendChild(t);const n=function(o){QRCode.toCanvas(t,o,{width:256,margin:2,color:{dark:'#7B61FF',light:'#1A1A24'}},function(e){e&&(t.getContext('2d').clearRect(0,0,t.width,t.height),console.error('生成失败:',e))})};n('https://github.com');e.addEventListener('input',function(e){const o=e.target.value.trim();o?n(o):t.getContext('2d').clearRect(0,0,t.width,t.height)})"
}

#### 组件设计最佳实践

- **模块化设计**：每个组件应设计为独立的模块，具备单一职责，便于维护和复用。
- **可扩展性**：组件应支持扩展，以适应不同的应用需求，允许通过参数或配置进行定制化。
- **响应式布局**：确保组件在不同设备和屏幕尺寸下均能良好展示，采用灵活的布局和样式。
- **错误处理**：在组件逻辑中加入充分的错误处理机制，确保在异常情况下能够提供友好的用户反馈。
- **性能优化**：优化组件的渲染和更新逻辑，减少不必要的资源消耗和性能开销，提升整体应用的响应速度。

#### 最终输出

请根据上述指导，生成完整的应用页面渲染 JSON。每个组件的配置应详细描述其功能、依赖项、输入输出逻辑及动态更新机制，确保整个应用具备高度的专业性和复杂性。
 
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
