"""Main App Module"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from api.v1.routes import api_version_one
from api.v1.schemas.main import ProbeServerResponse, HomeResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan function"""

    yield


app = FastAPI(
    lifespan=lifespan,
    title="FastAPI Authentication System",
    description="Welcome to FastAPI Authentication system by [Ajiboye Pius A.](https://ajiboye-pius.vercel.app)",
    version="1.0.0",
    license_info={"name": "ISC", "url": "https://ajiboye-pius.vercel.app"},
    contact={
        "name": "AuthSystem API Support",
        "url": "https://ajiboye-pius.vercel.app",
        "email": "ajiboyeadeleye080@gmail.com",
    },
    terms_of_service="https://ajiboye-pius.vercel.app",
    # root_path="/api/auth",
    # root_path_in_servers=False,
)

# CROSS-ORIGIN MIDDLEWARE
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/probe",
    tags=["General"],
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
    "/", tags=["General"], status_code=status.HTTP_200_OK, response_model=HomeResponse
)
async def home():
    """
    Homepage
    """

    return {
        "message": "Welcome to FastAPI Auth System by Pius",
        "status_code": status.HTTP_200_OK,
        "data": {
            "author": {
                "name": "Ajiboye Pius A.",
                "website": "https://ajiboye-pius.vercel.app",
                "github": "https://github.com/Adeleye080",
            },
            "URL": {},
        },
    }


app.include_router(api_version_one)
