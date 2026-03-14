package tools

import "zai-proxy/internal/model"

// GetBuiltinTools 返回所有内置工具定义
func GetBuiltinTools() []model.Tool {
	return []model.Tool{
		// 多功能助手
		{
			Type: "function",
			Function: model.ToolFunction{
				Name:        "get_current_time",
				Description: "获取当前时间，支持不同时区和格式",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"timezone": map[string]interface{}{
							"type":        "string",
							"description": "时区名称（如 Asia/Shanghai, America/New_York）",
						},
						"format": map[string]interface{}{
							"type":        "string",
							"description": "时间格式（如 2006-01-02 15:04:05）",
						},
					},
					"required": []string{},
				},
			},
		},
		{
			Type: "function",
			Function: model.ToolFunction{
				Name:        "calculate",
				Description: "执行数学计算，支持基本运算和高级数学函数",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"expression": map[string]interface{}{
							"type":        "string",
							"description": "数学表达式（如 2+3*4, sqrt(16), sin(pi/2)）",
						},
					},
					"required": []string{"expression"},
				},
			},
		},
		{
			Type: "function",
			Function: model.ToolFunction{
				Name:        "search_web",
				Description: "搜索网络获取实时信息",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"query": map[string]interface{}{
							"type":        "string",
							"description": "搜索关键词",
						},
						"num_results": map[string]interface{}{
							"type":        "integer",
							"description": "返回结果数量，默认5",
						},
					},
					"required": []string{"query"},
				},
			},
		},
		// 数据库查询
		{
			Type: "function",
			Function: model.ToolFunction{
				Name:        "query_database",
				Description: "执行SQL查询获取数据",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"sql": map[string]interface{}{
							"type":        "string",
							"description": "SQL查询语句",
						},
						"database": map[string]interface{}{
							"type":        "string",
							"description": "目标数据库名称",
						},
					},
					"required": []string{"sql"},
				},
			},
		},
		// 文件操作
		{
			Type: "function",
			Function: model.ToolFunction{
				Name:        "file_operations",
				Description: "执行文件操作，支持读取、写入和列出文件",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"operation": map[string]interface{}{
							"type":        "string",
							"enum":        []string{"read", "write", "list"},
							"description": "操作类型：read（读取）、write（写入）、list（列出）",
						},
						"path": map[string]interface{}{
							"type":        "string",
							"description": "文件或目录路径",
						},
						"content": map[string]interface{}{
							"type":        "string",
							"description": "写入内容（仅 write 操作需要）",
						},
					},
					"required": []string{"operation", "path"},
				},
			},
		},
		// API集成
		{
			Type: "function",
			Function: model.ToolFunction{
				Name:        "call_external_api",
				Description: "调用外部API接口",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"url": map[string]interface{}{
							"type":        "string",
							"description": "API请求URL",
						},
						"method": map[string]interface{}{
							"type":        "string",
							"enum":        []string{"GET", "POST", "PUT", "DELETE"},
							"description": "HTTP请求方法",
						},
						"headers": map[string]interface{}{
							"type":        "object",
							"description": "请求头",
						},
						"body": map[string]interface{}{
							"type":        "string",
							"description": "请求体（JSON字符串）",
						},
					},
					"required": []string{"url", "method"},
				},
			},
		},
	}
}
