from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Access PoC v8"
    environment: str = Field(default="dev", alias="ENVIRONMENT")
    database_url: str = Field(default="sqlite:///./access_poc_v8.db", alias="DATABASE_URL")
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")
    jwt_secret: str = Field(default="dev-secret-change-me", alias="JWT_SECRET")
    jwt_algorithm: str = "HS256"
    jwt_active_kid: str = Field(default="v1", alias="JWT_ACTIVE_KID")
    jwt_keyring_json: str = Field(default="", alias="JWT_KEYRING_JSON")
    secret_encryption_key: str = Field(default="dev-secret-encryption-key", alias="SECRET_ENCRYPTION_KEY")
    access_token_ttl_seconds: int = 300
    api_key_header: str = "X-API-Key"
    client_id_header: str = "X-Client-Id"
    tenant_id_header: str = "X-Tenant-Id"
    admin_api_key_header: str = "X-Admin-Api-Key"
    admin_api_key: str = Field(default="admin-dev-key", alias="ADMIN_API_KEY")
    prometheus_enabled: bool = True
    rate_limit_per_minute: int = 60
    request_cache_ttl_seconds: int = 15
    fail_closed: bool = True
    structured_logging: bool = True
    webhook_secret_pepper: str = Field(default="webhook-pepper", alias="WEBHOOK_SECRET_PEPPER")
    webhook_signature_header: str = "X-Webhook-Signature"
    webhook_timestamp_header: str = "X-Webhook-Timestamp"
    webhook_event_id_header: str = "X-Webhook-Event-Id"
    webhook_delivery_id_header: str = "X-Webhook-Delivery-Id"
    outbox_batch_size: int = 100
    outbox_poll_interval_seconds: int = 5
    webhook_timeout_seconds: int = 5
    webhook_max_attempts: int = 5
    request_decision_version: str = "v8.2"
    ip_hash_pepper: str = Field(default="ip-pepper", alias="IP_HASH_PEPPER")
    metrics_api_key: str = Field(default="", alias="METRICS_API_KEY")

    @model_validator(mode="after")
    def validate_production_secrets(self):
        if self.environment.lower() != "prod":
            return self
        weak_values = {
            "dev-secret-change-me",
            "admin-dev-key",
            "dev-secret-encryption-key",
            "ip-pepper",
            "webhook-pepper",
            "replace-with-random-admin-key",
            "replace-with-32-byte-secret",
            "replace-with-ip-pepper",
            "replace-with-webhook-pepper",
        }
        checks = {
            "ADMIN_API_KEY": self.admin_api_key,
            "SECRET_ENCRYPTION_KEY": self.secret_encryption_key,
            "IP_HASH_PEPPER": self.ip_hash_pepper,
            "WEBHOOK_SECRET_PEPPER": self.webhook_secret_pepper,
        }
        for name, value in checks.items():
            if not value or value in weak_values or len(value) < 24:
                raise ValueError(f"{name} must be a strong production secret")
        if not self.jwt_keyring_json and (self.jwt_secret in weak_values or len(self.jwt_secret) < 24):
            raise ValueError("JWT_KEYRING_JSON or JWT_SECRET must contain a strong production signing secret")
        if "postgres:postgres" in self.database_url:
            raise ValueError("DATABASE_URL must not use the default postgres password in production")
        if self.prometheus_enabled and (not self.metrics_api_key or len(self.metrics_api_key) < 24):
            raise ValueError("METRICS_API_KEY must be set when Prometheus metrics are enabled in production")
        return self

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)


settings = Settings()
