from fastapi import FastAPI
from app.auth import router as auth_router

app = FastAPI(title='FastAPI JWT Authentication')

app.include_router(auth_router)
