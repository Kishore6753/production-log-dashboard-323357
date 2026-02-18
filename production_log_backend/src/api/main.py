from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes.log_analysis import router as log_analysis_router
from src.core.config import get_settings

settings = get_settings()

openapi_tags = [
    {
        "name": "System",
        "description": "Health checks and general system endpoints.",
    },
    {
        "name": "Log analysis",
        "description": (
            "Upload logs, run parsing/analysis per production-log-analysis skill rules, "
            "and retrieve structured reports."
        ),
    },
]

app = FastAPI(
    title=settings.app_title,
    description=settings.app_description,
    version=settings.app_version,
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["System"], summary="Health Check")
# PUBLIC_INTERFACE
def health_check():
    """Simple liveness endpoint."""
    return {"message": "Healthy"}


app.include_router(log_analysis_router)
