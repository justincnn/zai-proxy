# zai-proxy

zai-proxy 是一个基于 Go 语言的代理服务，将 z.ai 网页聊天转换为 OpenAI API 兼容格式。用户使用自己的 z.ai token 进行调用。

## 功能特性

- OpenAI API 兼容格式
- 支持流式和非流式响应
- 支持多种 GLM 模型
- 支持思考模式 (thinking)
- 支持联网搜索模式 (search)
- 支持内置工具调用 (tools)
- 支持多模态图片输入
- 支持匿名 Token（免登录）
- **自动生成签名**
- **自动更新签名版本号**

## 快速开始

### 安装运行

```bash
# 克隆项目
git clone https://github.com/kao0312/zai-proxy.git
cd zai-proxy

# 安装依赖
go mod download

# 运行服务
go run main.go
```

### Docker 一键部署

```bash
docker run -d -p 8000:8000 ghcr.io/kao0312/zai-proxy:latest
```

自定义端口和日志级别：

```bash
docker run -d -p 8080:8000 -e LOG_LEVEL=debug ghcr.io/kao0312/zai-proxy:latest
```

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| PORT | 监听端口 | 8000 |
| LOG_LEVEL | 日志级别 | info |

## 获取 z.ai Token

### 方式一：使用匿名 Token（免登录）

直接使用 `free` 作为 API key，服务会自动获取一个匿名 token：

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer free" \
  -H "Content-Type: application/json" \
  -d '{"model": "GLM-4.7", "messages": [{"role": "user", "content": "hello"}]}'
```

### 方式二：使用个人 Token

1. 登录 https://chat.z.ai
2. 打开浏览器开发者工具 (F12)
3. 切换到 Application/Storage 标签
4. 在 Cookies 中找到 `token` 字段
5. 复制其值作为 API 调用的 Authorization

## 支持的模型

| 模型名称 | 上游模型 |
|----------|----------|
| GLM-4.5 | 0727-360B-API |
| GLM-4.6 | GLM-4-6-API-V1 |
| GLM-4.7 | glm-4.7 |
| GLM-4.5-V | glm-4.5v |
| GLM-4.6-V | glm-4.6v |
| GLM-4.5-Air | 0727-106B-API |

### 模型标签

模型名称支持以下后缀标签（可组合使用）：

- `-thinking`: 启用思考模式，响应会包含 `reasoning_content` 字段
- `-search`: 启用联网搜索模式
- `-tools`: 自动注入内置工具定义，模型会返回 `tool_calls` 进行函数调用
- (TODO) `-deepsearch`: 启用多轮搜索，深入研究分析

标签可任意组合，顺序不限：

示例：

- `GLM-4.7-thinking`
- `GLM-4.7-search`
- `GLM-4.7-thinking-search`
- `GLM-4.7-tools`
- `GLM-4.7-tools-thinking`

## 使用示例

### curl 测试

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer YOUR_ZAI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-4.7",
    "messages": [{"role": "user", "content": "hello"}],
    "stream": true
  }'
```

### 多模态请求：

```json
{
  "model": "GLM-4.6-V",
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "text", "text": "描述这张图片"},
        {"type": "image_url", "image_url": {"url": "https://example.com/image.jpg"}}
      ]
    }
  ]
}
```

### 支持的图片格式：
- HTTP/HTTPS URL
- Base64 编码 (data:image/jpeg;base64,...)

## 工具调用 (Function Calling)

使用 `-tools` 后缀时，代理会自动注入 6 个内置工具定义。模型会根据用户输入决定是否调用工具。

### 内置工具

| 工具名 | 描述 |
|--------|------|
| `get_current_time` | 获取当前时间 |
| `calculate` | 执行数学计算 |
| `search_web` | 搜索网络信息 |
| `query_database` | 执行SQL查询 |
| `file_operations` | 文件读写列表 |
| `call_external_api` | 调用外部API |

### 基本调用

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer YOUR_ZAI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-4.7-tools",
    "messages": [{"role": "user", "content": "现在几点了？"}],
    "stream": true
  }'
```

模型会返回 `tool_calls`（`finish_reason` 为 `"tool_calls"`），由客户端自行执行工具并将结果发回。

### 多轮调用流程

```
第1轮：用户提问 → 模型返回 tool_calls
第2轮：发送工具执行结果 → 模型生成最终回答
```

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer YOUR_ZAI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-4.7-tools",
    "messages": [
      {"role": "user", "content": "现在几点了？"},
      {"role": "assistant", "content": "", "tool_calls": [
        {"id": "call_xxx", "type": "function", "function": {"name": "get_current_time", "arguments": "{}"}}
      ]},
      {"role": "tool", "tool_call_id": "call_xxx", "content": "{\"time\": \"2026-03-14 15:30:00\"}"}
    ],
    "stream": true
  }'
```

### 自定义工具

也可以不使用 `-tools` 后缀，直接在请求中传入 `tools` 字段（标准 OpenAI 格式）：

```json
{
  "model": "GLM-4.7",
  "messages": [{"role": "user", "content": "北京天气怎么样？"}],
  "tools": [{
    "type": "function",
    "function": {
      "name": "get_weather",
      "description": "获取天气信息",
      "parameters": {
        "type": "object",
        "properties": {
          "city": {"type": "string", "description": "城市名称"}
        },
        "required": ["city"]
      }
    }
  }],
  "tool_choice": "auto"
}
```

两者可混合使用：`-tools` 模型名 + 自定义 `tools` 字段。**客户端自带的同名工具优先**，不会被内置工具覆盖。
