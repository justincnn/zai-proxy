package internal

import (
	"regexp"
	"strings"
)

// 基础模型映射（不包含标签后缀）
var BaseModelMapping = map[string]string{
	"GLM-4.5":     "0727-360B-API",
	"GLM-4.6":     "GLM-4-6-API-V1",
	"GLM-4.5-V":   "glm-4.5v",
	"GLM-4.5-Air": "0727-106B-API",
}

// v1/models 返回的模型列表（不包含所有标签组合）
var ModelList = []string{
	"GLM-4.5",
	"GLM-4.6",
	"GLM-4.5-thinking",
	"GLM-4.6-thinking",
	"GLM-4.5-V",
	"GLM-4.5-Air",
}

// 解析模型名称，提取基础模型名和标签
// 支持 -thinking 和 -search 标签的任意排列组合
func ParseModelName(model string) (baseModel string, enableThinking bool, enableSearch bool) {
	enableThinking = false
	enableSearch = false
	baseModel = model

	// 检查并移除 -thinking 和 -search 标签（任意顺序）
	for {
		if strings.HasSuffix(baseModel, "-thinking") {
			enableThinking = true
			baseModel = strings.TrimSuffix(baseModel, "-thinking")
		} else if strings.HasSuffix(baseModel, "-search") {
			enableSearch = true
			baseModel = strings.TrimSuffix(baseModel, "-search")
		} else {
			break
		}
	}

	return baseModel, enableThinking, enableSearch
}

func IsThinkingModel(model string) bool {
	_, enableThinking, _ := ParseModelName(model)
	return enableThinking
}

func IsSearchModel(model string) bool {
	_, _, enableSearch := ParseModelName(model)
	return enableSearch
}

func GetTargetModel(model string) string {
	baseModel, _, _ := ParseModelName(model)
	if target, ok := BaseModelMapping[baseModel]; ok {
		return target
	}
	return model
}

// OpenAI 格式的消息内容项
type ContentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

type ImageURL struct {
	URL string `json:"url"`
}

// Message 支持纯文本和多模态内容
type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // string 或 []ContentPart
}

// 解析消息内容，返回文本和图片URL列表
func (m *Message) ParseContent() (text string, imageURLs []string) {
	switch content := m.Content.(type) {
	case string:
		return content, nil
	case []interface{}:
		for _, item := range content {
			if part, ok := item.(map[string]interface{}); ok {
				partType, _ := part["type"].(string)
				if partType == "text" {
					if t, ok := part["text"].(string); ok {
						text += t
					}
				} else if partType == "image_url" {
					if imgURL, ok := part["image_url"].(map[string]interface{}); ok {
						if url, ok := imgURL["url"].(string); ok {
							imageURLs = append(imageURLs, url)
						}
					}
				}
			}
		}
	}
	return text, imageURLs
}

// 转换为上游消息格式（纯文本）
func (m *Message) ToUpstreamMessage() map[string]string {
	text, _ := m.ParseContent()
	return map[string]string{
		"role":    m.Role,
		"content": text,
	}
}

type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type ChatCompletionChunk struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
}

type Choice struct {
	Index        int          `json:"index"`
	Delta        Delta        `json:"delta,omitempty"`
	Message      *MessageResp `json:"message,omitempty"`
	FinishReason *string      `json:"finish_reason"`
}

type Delta struct {
	Content          string `json:"content,omitempty"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

type MessageResp struct {
	Role             string `json:"role"`
	Content          string `json:"content"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
}

type ModelsResponse struct {
	Object string       `json:"object"`
	Data   []ModelInfo  `json:"data"`
}

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

// 搜索引用标记正则：【turn数字search数字】
var searchRefPattern = regexp.MustCompile(`【turn\d+search\d+】`)

// 搜索引用标记可能的前缀模式
var searchRefPrefixPattern = regexp.MustCompile(`【(t(u(r(n(\d+(s(e(a(r(c(h(\d+)?)?)?)?)?)?)?)?)?)?)?)?$`)

// SearchRefFilter 用于跨流过滤搜索引用标记
type SearchRefFilter struct {
	buffer string
}

// NewSearchRefFilter 创建新的过滤器
func NewSearchRefFilter() *SearchRefFilter {
	return &SearchRefFilter{}
}

// Process 处理内容，返回可以安全输出的部分
// 如果末尾有可能是引用标记的前缀，会暂存起来
func (f *SearchRefFilter) Process(content string) string {
	// 合并之前暂存的内容
	content = f.buffer + content
	f.buffer = ""

	// 先移除完整的引用标记
	content = searchRefPattern.ReplaceAllString(content, "")

	if content == "" {
		return ""
	}

	// 检查末尾是否有可能是引用标记的前缀
	// 从末尾开始，最多检查【turn999search999】长度（约20字符）
	maxPrefixLen := 20
	if len(content) < maxPrefixLen {
		maxPrefixLen = len(content)
	}

	for i := 1; i <= maxPrefixLen; i++ {
		suffix := content[len(content)-i:]
		if searchRefPrefixPattern.MatchString(suffix) {
			// 找到可能的前缀，暂存起来
			f.buffer = suffix
			return content[:len(content)-i]
		}
	}

	return content
}

// Flush 返回所有暂存的内容（流结束时调用）
func (f *SearchRefFilter) Flush() string {
	result := f.buffer
	f.buffer = ""
	return result
}

// 检查是否为搜索结果内容（需要跳过）
func IsSearchResultContent(editContent string) bool {
	return strings.Contains(editContent, `"search_result"`)
}

// 检查是否为搜索工具调用内容（需要跳过）
func IsSearchToolCall(editContent string, phase string) bool {
	if phase != "tool_call" {
		return false
	}
	// tool_call 阶段包含 mcp 相关内容的都跳过
	return strings.Contains(editContent, `"mcp"`) || strings.Contains(editContent, `mcp-server`)
}
