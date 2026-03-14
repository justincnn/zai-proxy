package tools

import (
	"encoding/json"
	"fmt"
	"strings"

	"zai-proxy/internal/model"
)

// BuildToolSystemPrompt 将工具定义列表转换为 system prompt 文本，
// 指示模型使用 <tool_call> 格式输出工具调用。
func BuildToolSystemPrompt(tools []model.Tool, toolChoice interface{}) string {
	if len(tools) == 0 {
		return ""
	}

	var sb strings.Builder

	sb.WriteString("# 工具调用规则\n\n")
	sb.WriteString("你可以使用下面列出的工具。当你需要调用工具时，**必须严格使用以下 XML 格式**输出调用请求（不要使用 markdown 代码块、不要使用 [TOOL] 或其他格式）：\n\n")
	sb.WriteString("<tool_call>{\"name\": \"函数名\", \"arguments\": {\"参数名\": \"参数值\"}}</tool_call>\n\n")
	sb.WriteString("**重要规则：**\n")
	sb.WriteString("- 你不能自行执行工具，只能输出 <tool_call> 标签，由系统执行后将结果返回给你\n")
	sb.WriteString("- 每个工具调用必须独立包裹在 <tool_call></tool_call> 标签中\n")
	sb.WriteString("- arguments 必须是合法 JSON 对象\n")
	sb.WriteString("- 不要在 <tool_call> 标签外描述调用参数\n\n")

	sb.WriteString("## 示例\n\n")
	sb.WriteString("用户: 帮我创建一个文件 test.txt 内容为 hello\n")
	sb.WriteString("助手: 好的，我来为您创建文件。\n")
	sb.WriteString("<tool_call>{\"name\": \"create_file\", \"arguments\": {\"filename\": \"test.txt\", \"content\": \"hello\"}}</tool_call>\n\n")
	sb.WriteString("用户: 查询北京和上海的天气\n")
	sb.WriteString("助手: 我来查询这两个城市的天气。\n")
	sb.WriteString("<tool_call>{\"name\": \"get_weather\", \"arguments\": {\"location\": \"北京\"}}</tool_call>\n")
	sb.WriteString("<tool_call>{\"name\": \"get_weather\", \"arguments\": {\"location\": \"上海\"}}</tool_call>\n\n")

	sb.WriteString("## 可用工具\n\n")

	for _, tool := range tools {
		sb.WriteString(fmt.Sprintf("### %s\n", tool.Function.Name))
		if tool.Function.Description != "" {
			sb.WriteString(fmt.Sprintf("%s\n", tool.Function.Description))
		}
		if tool.Function.Parameters != nil {
			params, err := json.Marshal(tool.Function.Parameters)
			if err == nil {
				sb.WriteString(fmt.Sprintf("Parameters: %s\n", string(params)))
			}
		}
		sb.WriteString("\n")
	}

	// 处理 tool_choice
	if toolChoice != nil {
		switch tc := toolChoice.(type) {
		case string:
			switch tc {
			case "none":
				sb.WriteString("**禁止调用任何工具，直接回答问题。**\n")
			case "required":
				sb.WriteString("**你的回复中必须包含至少一个 <tool_call> 标签。即使你认为不需要调用工具，也必须调用。**\n")
			// "auto" is the default, no special instruction needed
			}
		case map[string]interface{}:
			// tool_choice = {"type": "function", "function": {"name": "xxx"}}
			if fn, ok := tc["function"].(map[string]interface{}); ok {
				if name, ok := fn["name"].(string); ok {
					sb.WriteString(fmt.Sprintf("**你必须调用工具 \"%s\"，使用 <tool_call> 标签输出调用。**\n", name))
				}
			}
		}
	}

	return sb.String()
}

// ConvertToolCallToText 将 assistant 消息中的 tool_calls 转换为 <tool_call> 文本格式，
// 用于在 prompt 注入模式下将历史 tool_calls 传给上游。
func ConvertToolCallToText(toolCalls []model.ToolCall) string {
	var parts []string
	for _, tc := range toolCalls {
		callJSON, _ := json.Marshal(map[string]interface{}{
			"name":      tc.Function.Name,
			"arguments": json.RawMessage(tc.Function.Arguments),
		})
		parts = append(parts, fmt.Sprintf("<tool_call>%s</tool_call>", string(callJSON)))
	}
	return strings.Join(parts, "\n")
}

// ConvertToolResultToText 将 tool 角色的消息转换为文本格式，
// 用于在 prompt 注入模式下传递工具执行结果。
func ConvertToolResultToText(toolCallID string, content string) string {
	return fmt.Sprintf("<tool_result call_id=\"%s\">%s</tool_result>", toolCallID, content)
}
