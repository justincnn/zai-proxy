package filter

import (
	"encoding/json"
	"regexp"
	"strings"

	"zai-proxy/internal/model"
)

var glmToolCallBlockPattern = regexp.MustCompile(`<glm_block[^>]*type="tool_call"[^>]*>([\s\S]*?)</glm_block>`)

// IsFunctionToolCall 判断 tool_call 阶段的内容是否是用户定义的函数调用（非 mcp/search）
func IsFunctionToolCall(editContent string, phase string) bool {
	if phase != "tool_call" {
		return false
	}
	// 排除 mcp / search 类型的 tool call
	if strings.Contains(editContent, `"mcp"`) || strings.Contains(editContent, `mcp-server`) {
		return false
	}
	if strings.Contains(editContent, `"search_result"`) || strings.Contains(editContent, `"search_image"`) {
		return false
	}
	// 包含函数调用特征
	return strings.Contains(editContent, `"function"`) || strings.Contains(editContent, `"arguments"`)
}

// ParseFunctionToolCalls 从上游 edit_content 解析函数调用
func ParseFunctionToolCalls(editContent string) []model.ToolCall {
	// 尝试从 glm_block 中提取
	matches := glmToolCallBlockPattern.FindAllStringSubmatch(editContent, -1)
	if len(matches) > 0 {
		var allCalls []model.ToolCall
		for _, match := range matches {
			if calls := parseToolCallJSON(match[1]); len(calls) > 0 {
				allCalls = append(allCalls, calls...)
			}
		}
		if len(allCalls) > 0 {
			return allCalls
		}
	}

	// 尝试直接解析为 JSON
	return parseToolCallJSON(editContent)
}

// parseToolCallJSON 解析 tool call JSON 数据
func parseToolCallJSON(content string) []model.ToolCall {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}

	// 尝试解析为单个 tool call 对象
	var single struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	if err := json.Unmarshal([]byte(content), &single); err == nil {
		if single.Function.Name != "" {
			return []model.ToolCall{{
				ID:   single.ID,
				Type: "function",
				Function: model.FunctionCall{
					Name:      single.Function.Name,
					Arguments: single.Function.Arguments,
				},
			}}
		}
		if single.Name != "" {
			return []model.ToolCall{{
				ID:   single.ID,
				Type: "function",
				Function: model.FunctionCall{
					Name:      single.Name,
					Arguments: single.Arguments,
				},
			}}
		}
	}

	// 尝试解析为数组
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(content), &arr); err == nil {
		var calls []model.ToolCall
		for _, raw := range arr {
			if parsed := parseToolCallJSON(string(raw)); len(parsed) > 0 {
				calls = append(calls, parsed...)
			}
		}
		return calls
	}

	return nil
}
