from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    environment: str = "development"
    database_url: str = "postgresql+psycopg://fieldnote:fieldnote@postgres:5432/fieldnote"
    redis_url: str = "redis://redis:6379/0"
    oidc_issuer: str = "http://keycloak:8080/realms/fieldnote"
    oidc_audience: str = "fieldnote-api"
    oidc_jwks_url: str = "http://keycloak:8080/realms/fieldnote/protocol/openid-connect/certs"
    oidc_dev_tenant: str = "demo-agency"
    require_mfa: bool = True
    s3_endpoint_url: str = "http://minio:9000"
    s3_region: str = "us-east-1"
    s3_bucket: str = "fieldnote-evidence"
    s3_access_key: str = "fieldnote-local"
    s3_secret_key: str = "fieldnote-local-secret"
    evidence_encryption_key: str = ""
    zap_api_url: str = "http://zap:8080"
    zap_api_key: str = ""
    nvd_api_key: str = ""
    nmap_max_rate: int = 20
    otel_exporter_otlp_endpoint: str = "http://otel-collector:4317"

@lru_cache
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
