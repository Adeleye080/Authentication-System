"""Main App Module"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, status, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from api.v1.routes import api_version_one
from api.v1.schemas.main import ProbeServerResponse, HomeResponse
from api.core.logging.logging_config import setup_logging  # type: ignore
from fastapi.templating import Jinja2Templates


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


# LOGGING SETUP
setup_logging()


email_templates = Jinja2Templates(directory="smtp/templates/html_mail_templates")


@app.get(
    "/", tags=["Home"], status_code=status.HTTP_200_OK, response_model=HomeResponse
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
                "name": "Ajiboye Pius Adeleye",
                "website": "https://ajiboye-pius.vercel.app",
                "github": "https://github.com/Adeleye080",
            },
            "URL": "site_url",
        },
    }


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


app.include_router(api_version_one)


# REGISTER EXCEPTION HANDLERS
@app.exception_handler(HTTPException)
async def http_exception(request: Request, exc: HTTPException):
    """HTTP exception handler"""

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "status_code": exc.status_code,
            "message": exc.detail,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception(request: Request, exc: RequestValidationError):
    """Validation exception handler"""

    errors = [
        {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]

    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "status_code": 422,
            "message": "Invalid input",
            "errors": errors,
        },
    )
