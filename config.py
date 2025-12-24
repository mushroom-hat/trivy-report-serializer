from pydantic_settings import BaseSettings
from typing import Literal

class Settings(BaseSettings):
  database_url: str = "postgresql://postgres:postgres@postgresql:5432/trivy"
  env: str = "dev"
  site: str = "local"
  sla_days: int = 90
  mode: Literal["hub", "non-hub"] = "non-hub"
  hub_url: str = "http://localhost:80"
  api_key: str = "changeme"
  log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
  class Config:
      env_file = ".env"


settings = Settings()
