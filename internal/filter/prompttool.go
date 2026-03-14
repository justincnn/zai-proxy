package filter

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"zai-proxy/internal/model"
)

// promptToolCallPattern 匹配 <tool_call>...</tool_call> 块
var promptToolCallPattern = regexp.MustCompile(`<tool_call>\s*([\s\S]*?)\s*</tool_call>`)

// altToolCallPattern 匹配 [TOOL]...[/TOOL] 和 [TOOL_CALL]...[/TOOL_CALL] 格式
var altToolCallPattern = regexp.MustCompile(`\[TOOL(?:_CALL)?\]\s*([\s\S]*?)\s*\[/TOOL(?:_CALL)?\]`)

// jsonBlockPattern 匹配 markdown JSON 代码块中的 tool call
var jsonBlockPattern = regexp.MustCompile("```json\\s*\\n(\\{[\\s\\S]*?\"name\"[\\s\\S]*?\\})\\s*\\n```")

// allToolCallPatterns 按优先级排列的所有 tool call 模式
var allToolCallPatterns = []*regexp.Regexp{
	promptToolCallPattern, // <tool_call> 最高优先级
	altToolCallPattern,    // [TOOL] / [TOOL_CALL]
	jsonBlockPattern,      // ```json ... ```
}

// ExtractPromptToolCalls 从文本中提取所有 tool call 块（支持多种格式），
// 返回清理后的文本和解析出的 tool calls。
func ExtractPromptToolCalls(content string) (cleanContent string, toolCalls []model.ToolCall) {
	var allCalls []model.ToolCall
	cleaned := content

	// 按优先级依次尝试各种格式
	for _, pattern := range allToolCallPatterns {
		matches := pattern.FindAllStringSubmatchIndex(cleaned, -1)
		if len(matches) == 0 {
			continue
		}

		// 从后向前移除匹配块，避免索引偏移
		for i := len(matches) - 1; i >= 0; i-- {
			match := matches[i]
			fullStart, fullEnd := match[0], match[1]
			groupStart, groupEnd := match[2], match[3]

			jsonStr := cleaned[groupStart:groupEnd]
			if calls := parsePromptToolCallJSON(jsonStr); len(calls) > 0 {
				allCalls = append(calls, allCalls...)
			}

			cleaned = cleaned[:fullStart] + cleaned[fullEnd:]
		}
	}

	if len(allCalls) == 0 {
		return content, nil
	}

	// 清理多余空行
	cleaned = strings.TrimSpace(cleaned)
	for strings.Contains(cleaned, "\n\n\n") {
		cleaned = strings.ReplaceAll(cleaned, "\n\n\n", "\n\n")
	}

	// 为每个 tool call 分配 ID
	for i := range allCalls {
		if allCalls[i].ID == "" {
			allCalls[i].ID = fmt.Sprintf("call_%s", uuid.New().String()[:24])
		}
		allCalls[i].Index = i
		allCalls[i].Type = "function"
	}

	return cleaned, allCalls
}

// parsePromptToolCallJSON 解析 <tool_call> 内的 JSON
func parsePromptToolCallJSON(content string) []model.ToolCall {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}

	// 标准格式: {"name": "xxx", "arguments": {...}}
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal([]byte(content), &call); err == nil && call.Name != "" {
		argsStr := string(call.Arguments)
		// 如果 arguments 不是字符串，序列化为字符串
		if len(argsStr) > 0 && argsStr[0] != '"' {
			// 已经是 JSON 对象/其他类型，直接用
		} else {
			// 是 JSON 字符串，解引用
			var s string
			if json.Unmarshal(call.Arguments, &s) == nil {
				argsStr = s
			}
		}
		return []model.ToolCall{{
			Function: model.FunctionCall{
				Name:      call.Name,
				Arguments: argsStr,
			},
		}}
	}

	return nil
}

// HasPromptToolCallOpen 检测文本中是否有未关闭的 tool call 标签
func HasPromptToolCallOpen(content string) bool {
	// <tool_call>
	if strings.Count(content, "<tool_call>") > strings.Count(content, "</tool_call>") {
		return true
	}
	// [TOOL] / [TOOL_CALL]
	if strings.Count(content, "[TOOL]") > strings.Count(content, "[/TOOL]") {
		return true
	}
	if strings.Count(content, "[TOOL_CALL]") > strings.Count(content, "[/TOOL_CALL]") {
		return true
	}
	return false
}
