from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    gemini_api_key: str = ""
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    nvd_api_key: str = ""
    firebase_service_account_path: str = "./backend/firebase-service-account.json"
    firebase_project_id: str = ""
    cors_origins: str = "http://localhost:5173"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()
