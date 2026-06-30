from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # App
    APP_NAME: str = "FastAPI App"
    APP_ENV: str = "development"
    DEBUG: bool = True


    # Database
    DB_HOST: str
    DB_PORT: int = 3306
    DB_USER: str
    DB_PASSWORD: str
    DB_NAME: str

    # JWT -Access Token
    ACCESS_TOKEN_SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 20

    #JWT - Refresh Token
    REFRESH_TOKEN_SECRET_KEY: str
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    #JWT - OTP Token
    OTP_TOKEN_SECRET_KEY: str
    OTP_TOKEN_EXPIRE_MINUTES: int = 5

    ALGORITHM: str = "HS256"

    #OTP settings
    OTP_LENGTH: int = 6
    OTP_MAX_RETRY: int = 5
    
    #Cookie settings
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"

    # SMTP
    SMTP_HOST: str
    SMTP_PORT: int = 587
    SMTP_USERNAME: str
    SMTP_PASSWORD: str
    SMTP_FROM_EMAIL: str = "noreply@fastapiapp.com"


    #  CORS
    ALLOWED_ORIGINS: str =""


    @property
    def DATABASE_URL(self) -> str:
        return(
            f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()   