from fastapi import FastAPI, Depends, status, Request
from contextlib import asynccontextmanager
from api.v1.routes import api_version_one
from api.utils.json_response import JsonResponseDict
from api.v1.schemas.main import ProbeServerResponse, HomeResponse
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


@app.get(
    "/probe",
    tags=["Home"],
    status_code=status.HTTP_200_OK,
    response_model=ProbeServerResponse,
)
async def probe_server():
    """
    Probe the server
    """
    return {
        "message": "I am the Python FastAPI API responding to probe",
        "status": "Healthy ♥️",
    }


@app.get(
    "/", tags=["Home"], status_code=status.HTTP_200_OK, response_model=HomeResponse
)
async def home():
    """
    Homepage
    """
    return JsonResponseDict(
        message="Welcome to Pius Python FastAPI Auth System",
        status_code=status.HTTP_200_OK,
        data={"URL": ""},
    )


app.include_router(api_version_one)
