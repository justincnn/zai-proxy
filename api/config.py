import os
from pydantic_settings import BaseSettings
from typing import Dict, List


class Settings(BaseSettings):
    # Server settings
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8001"))
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    WORKERS: int = int(os.getenv("WORKERS", "1"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # API settings
    PROXY_URL: str = os.getenv("PROXY_URL", "https://chat.z.ai")

    # Headers
    HEADERS: Dict[str, str] = {
        "Accept": "*/*",
        "Accept-Language": "zh-CN",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "Origin": "https://chat.z.ai",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "X-FE-Version": "prod-fe-1.0.98",
    }

    ALLOWED_MODELS: List[Dict[str, str]] = [
        {"id": "glm-4.6", "name": "GLM-4.6"},
        {"id": "glm-4.5V", "name": "GLM-4.5V"},
        {"id": "glm-4.5", "name": "GLM-4.5"},
        {"id": "glm-4.6-search", "name": "GLM-4.6-SEARCH"},
        {"id": "glm-4.6-advanced-search", "name": "GLM-4.6-ADVANCED-SEARCH"},
        {"id": "glm-4.6-nothinking", "name": "GLM-4.6-NOTHINKING"},
    ]

    MODELS_MAPPING: Dict[str, str] = {
        "glm-4.6": "GLM-4-6-API-V1",
        "glm-4.6-nothinking": "GLM-4-6-API-V1",
        "glm-4.6-search": "GLM-4-6-API-V1",
        "glm-4.6-advanced-search": "GLM-4-6-API-V1",
        "glm-4.5V": "glm-4.5v",
        "glm-4.5": "0727-360B-API",
    }



_settings = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
