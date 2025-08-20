from pydantic import AnyUrl, BaseSettings
import os

ENV = os.getenv("ENVIRONMENT", "development")  # lee variable del sistema
env_file = f".env.{ENV}"

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DATABASE_URL: AnyUrl
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    class Config:
        env_file = env_file
        env_file_encoding = "utf-8"

settings = Settings()