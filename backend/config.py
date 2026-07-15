from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    groq_api_key: str = ""
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    nvd_api_key: str = ""
    # Postgres connection string (e.g. Supabase). Blank = run stateless.
    database_url: str = ""
    cors_origins: str = "http://localhost:5173"
<<<<<<< HEAD
    # SMTP settings for email alerts (optional — leave blank to disable)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email: str = ""
=======
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()
