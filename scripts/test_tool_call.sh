#!/bin/bash
# 测试 tool/function calling 功能
# 用法: ./scripts/test_tool_call.sh [TOKEN] [BASE_URL]
#
# TOKEN 可以是你的 z.ai token 或 "free"（匿名）
# BASE_URL 默认 http://localhost:8000

TOKEN="${1:-free}"
BASE_URL="${2:-http://localhost:8000}"

echo "=== 测试 Tool/Function Calling ==="
echo "BASE_URL: $BASE_URL"
echo "TOKEN: ${TOKEN:0:10}..."
echo ""

# ===== 测试 1: 带 tools 的流式请求 =====
echo "--- 测试 1: 流式 tool calling ---"
curl -sS "${BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-4.7",
    "stream": true,
    "messages": [
      {"role": "user", "content": "北京今天天气怎么样？请调用 get_weather 函数查询。"}
    ],
    "tools": [{
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "获取指定城市的当前天气信息",
        "parameters": {
          "type": "object",
          "properties": {
            "location": {
              "type": "string",
              "description": "城市名称，如：北京"
            }
          },
          "required": ["location"]
        }
      }
    }],
    "tool_choice": "auto"
  }' 2>&1
echo ""
echo ""

# ===== 测试 2: 带 tools 的非流式请求 =====
echo "--- 测试 2: 非流式 tool calling ---"
curl -sS "${BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-4.7",
    "stream": false,
    "messages": [
      {"role": "user", "content": "帮我查一下上海的天气，用 get_weather 工具。"}
    ],
    "tools": [{
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "获取指定城市的当前天气信息",
        "parameters": {
          "type": "object",
          "properties": {
            "location": {
              "type": "string",
              "description": "城市名称"
            }
          },
          "required": ["location"]
        }
      }
    }],
    "tool_choice": "auto"
  }' 2>&1 | python3 -m json.tool 2>/dev/null || cat
echo ""
echo ""

# ===== 测试 3: 多工具 =====
echo "--- 测试 3: 多工具非流式 ---"
curl -sS "${BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-4.7",
    "stream": false,
    "messages": [
      {"role": "user", "content": "北京天气怎么样？现在几点了？请分别调用对应的工具。"}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "get_weather",
          "description": "获取天气",
          "parameters": {"type": "object", "properties": {"location": {"type": "string"}}, "required": ["location"]}
        }
      },
      {
        "type": "function",
        "function": {
          "name": "get_current_time",
          "description": "获取当前时间",
          "parameters": {"type": "object", "properties": {"timezone": {"type": "string"}}, "required": ["timezone"]}
        }
      }
    ],
    "tool_choice": "auto"
  }' 2>&1 | python3 -m json.tool 2>/dev/null || cat
echo ""
echo ""

# ===== 测试 4: 完整多轮对话（tool result 回传）=====
echo "--- 测试 4: 多轮对话 (tool result 回传) ---"
curl -sS "${BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-4.7",
    "stream": false,
    "messages": [
      {"role": "user", "content": "北京天气怎么样？"},
      {
        "role": "assistant",
        "content": "",
        "tool_calls": [{
          "id": "call_abc123",
          "type": "function",
          "function": {"name": "get_weather", "arguments": "{\"location\":\"北京\"}"}
        }]
      },
      {
        "role": "tool",
        "tool_call_id": "call_abc123",
        "content": "{\"temperature\": 25, \"condition\": \"晴\", \"humidity\": 40}"
      }
    ],
    "tools": [{
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "获取天气",
        "parameters": {"type": "object", "properties": {"location": {"type": "string"}}, "required": ["location"]}
      }
    }]
  }' 2>&1 | python3 -m json.tool 2>/dev/null || cat
echo ""
echo ""

# ===== 测试 5: 不带 tools 的普通请求（回归测试）=====
echo "--- 测试 5: 不带 tools 的普通请求（回归）---"
curl -sS "${BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-4.7",
    "stream": false,
    "messages": [
      {"role": "user", "content": "你好，1+1等于几？"}
    ]
  }' 2>&1 | python3 -m json.tool 2>/dev/null || cat
echo ""

echo "=== 测试完成 ==="
echo ""
echo "检查要点："
echo "  1. 测试 1/2: 查看响应中是否有 tool_calls 字段和 finish_reason=tool_calls"
echo "  2. 测试 3: 是否返回多个 tool_calls"
echo "  3. 测试 4: 模型是否基于 tool result 生成了自然语言回复"
echo "  4. 测试 5: 不带 tools 时是否正常返回文本（无 tool_calls 字段）"
echo "  5. 查看服务端日志中的 [ToolCall] 行，确认上游返回的原始格式"
