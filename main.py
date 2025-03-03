from fastapi import FastAPI, Depends, status
from contextlib import asynccontextmanager
from api.v1.routes import api_version_one
from api.utils.json_response import JsonResponseDict


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan function"""

    yield


app = FastAPI(
    lifespan=lifespan,
    title="FastAPI Authentication System",
    description="An Authentication system for FastAPI apps",
    version="1.0.0",
)


@app.get("/probe", tags=["Home"])
async def probe_server():
    """
    Probe the server
    """
    return {"message": "I am the Python FastAPI API responding"}


@app.get("/", tags=["Home"])
async def home():
    """
    Homepage
    """
    return JsonResponseDict(
        message="Welcome to API", status_code=status.HTTP_200_OK, data={"URL": ""}
    )


app.include_router(api_version_one)
