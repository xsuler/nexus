// main.go
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

const (
	PROMPT_TEMPLATE = `
用户希望实现app，需要渲染一个app页面，请你输出这个app页面的渲染json

你需要输出页面的json配置

### JSON 任务配置极简指南

{
    "name": "实时时钟",
    "action": "(input, update) => { setInterval(() => update(new Date().toLocaleTimeString()), 1000); }"
}

{
    "name": "二维码生成器",
    "dependencies": [
        "https://cdn.jsdelivr.net/npm/qrcode-svg@1.1.0/lib/qrcode.min.js"
    ],
    "input": {
        "render": "(container, update) => { const input = document.createElement('input'); input.className = 'input-field'; input.placeholder = '输入内容'; container.appendChild(input); }"
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
    "action": "(input, update) => { if (typeof input !== 'string' || !input.trim()) return; update(input.trim()); }"
}

请输出一个json，表达这个页面
注意：
1. json里面的string code都format成一行
2. 尽可能使用最新的稳定的cdn dependency, 确保js依赖可获取
3. output的input的data即为action的调用update的入参数
4. 不要使用await async等异步api
5. 使用jsDelivr作为依赖的cdn
6. 使用最广泛使用的js依赖，不要用小众依赖
7. js依赖都用最新版本
8. 尽可能使用js完成任务，不要引入dependencies
9. 某些js依赖是禁止的
10. 注意js输出中""需要被正确转义

以下是禁止使用的js依赖：
1. marked.min.js
2. jspdf.umd.min.js
3. three.js`
)

type GenerateRequest struct {
	Prompt string `json:"prompt"`
}

func handleGeneration(c *gin.Context) {
	apiKey := os.Getenv("DEEPSEEK_API_KEY")
	if apiKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器配置错误"})
		return
	}

	var req GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式"})
		return
	}

	// 构造完整的请求体
	requestBody := map[string]interface{}{
		"model": "deepseek-coder",
		"messages": []map[string]string{
			{"role": "system", "content": PROMPT_TEMPLATE},
			{"role": "user", "content": req.Prompt},
		},
		"response_format": map[string]string{"type": "json_object"},
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "请求构造失败"})
		return
	}

	// 创建代理请求
	proxyReq, _ := http.NewRequest(
		"POST",
		"https://api.deepseek.com/chat/completions",
		bytes.NewReader(bodyBytes),
	)

	proxyReq.Header.Set("Content-Type", "application/json")
	proxyReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "上游服务连接失败"})
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, v := range resp.Header {
		c.Writer.Header()[k] = v
	}

	// 流式传输响应体
	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

func main() {
	router := gin.Default()

	// 代理端点
	router.POST("/api/generate", handleGeneration)
	router.Static("/", "./frontend/")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	router.Run(":" + port)
}
