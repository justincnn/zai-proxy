package model

import "strings"

// 基础模型映射（不包含标签后缀）
var BaseModelMapping = map[string]string{
	"GLM-4.5":      "0727-360B-API",
	"GLM-4.6":      "GLM-4-6-API-V1",
	"GLM-4.7":      "glm-4.7",
	"GLM-4.5-V":    "glm-4.5v",
	"GLM-4.6-V":    "glm-4.6v",
	"GLM-4.5-Air":  "0727-106B-API",
	"0808-360B-DR": "0808-360B-DR",
}

// v1/models 返回的模型列表（不包含所有标签组合）
var ModelList = []string{
	"GLM-4.5",
	"GLM-4.6",
	"GLM-4.7",
	"GLM-4.7-thinking",
	"GLM-4.7-thinking-search",
	"GLM-4.5-V",
	"GLM-4.6-V",
	"GLM-4.6-V-thinking",
	"GLM-4.5-Air",
	// "0808-360B-DR",
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
