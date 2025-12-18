from pydantic_settings import BaseSettings

class Settings(BaseSettings):
  database_url: str = "postgresql://postgres:postgres@db:5432/trivy"
  env: str = "dev"
  site: str = "local"
  sla_days: int = 90

  class Config:
      env_file = ".env"


settings = Settings()
