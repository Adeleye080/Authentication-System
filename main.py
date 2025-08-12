"""Main App Module"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, status, Request, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from api.v1.routes import api_version_one
from api.v1.models.mmdb import MMDB_TRACKER
from api.v1.schemas.main import ProbeServerResponse, HomeResponse
from api.core.logging.logging_config import setup_logging
from fastapi.templating import Jinja2Templates
from api.utils.json_response import JsonResponseDict
from api.utils.schedulers import scheduler  # type: ignore
from api.utils.settings import settings
from starlette.middleware.sessions import SessionMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan function"""

    # STARTUP EVENTS
    # setup application level log
    setup_logging()
    # setup and register schedulers
    scheduler.start()
    # Initiate GeoIP tracker
    MMDB_TRACKER()

    yield

    # shutdown events
    scheduler.shutdown()


if settings.DEBUG_MODE:
    openapi_url = "/openapi.json"
else:
    openapi_url = None


app = FastAPI(
    lifespan=lifespan,
    title="FastAPI Authentication System",
    description="Welcome to FastAPI Authentication system by [Ajiboye Pius A.](https://ajiboye-pius.vercel.app)",
    version="1.0.0",
    license_info={"name": "MIT", "url": "https://ajiboye-pius.vercel.app"},
    contact={
        "name": "AuthSystem API Support",
        "url": "https://ajiboye-pius.vercel.app",
        "email": "ajiboyeadeleye080@gmail.com",
    },
    docs_url="/documentation",
    openapi_url=openapi_url,
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

#  SESSION MIDDLEWARE
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)


email_templates = Jinja2Templates(directory="smtp/templates/html_mail_templates")


@app.get("/", include_in_schema=False, status_code=status.HTTP_200_OK)
def root(request: Request):
    return RedirectResponse(url=request.url_for("home"))


@app.get(
    "/auth/system/home",
    tags=["Home"],
    status_code=status.HTTP_200_OK,
    response_model=HomeResponse,
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
            "contributors": [],
            "URL": "site_url",
            "documentation": "docs_url",
        },
    }


@app.get(
    "/auth/system/probe",
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

    return JsonResponseDict(
        status_code=exc.status_code,
        message=exc.detail,
        status="error",
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
            "message": f"Invalid input: {errors}",
        },
    )


# webhooks
@app.webhooks.post("oauth2-signup")
async def new_oauth2_signup():
    """
    When a new user signs up with the oauth2 flow, we will send you an `oauth2-signup` event POST request with this data
    to the webhook URL that you register with our system.

    **Security Requirements:**
    - If you use a firewall or IP allowlist, add this server's IP to the allowed list.
    - If your webhook endpoint is browser-based, ensure your CORS policy allows requests from this domain.
    """


@app.webhooks.post("user-hard-delete")
async def user_hard_delete():
    """
    When a user is deleted, we will send you a `user-hard-delete` event POST request with this data
    to the webhook URL that you register with our system.
    """
