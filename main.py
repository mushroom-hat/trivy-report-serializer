from fastapi import FastAPI
from routers.webhook import router as trivy_router

app = FastAPI()

app.include_router(trivy_router)
