from fastapi import APIRouter, HTTPException, Depends, status, Query
from sqlalchemy.orm import Session
from api.v1.schemas.country_blacklist import CountryBlacklistRequest, CountryBlacklistResponse  # type: ignore
from api.v1.services import user_service, country_blacklist_service
from api.v1.models.user import User
from db.database import get_db
from api.utils.json_response import JsonResponseDict


country_blacklist_router = APIRouter(tags=["Country Blacklisting"], prefix="/blacklist")


@country_blacklist_router.get(
    "/countries/get", response_model=list[CountryBlacklistResponse]
)
def get_all_blacklisted_countries(
    superadmin: User = Depends(user_service.get_current_superadmin),
    db: Session = Depends(get_db),
):
    """Get all blacklisted countries."""

    blacklisted_countries = country_blacklist_service.fetch_all(db)
    data = [country.to_dict() for country in blacklisted_countries]

    return JsonResponseDict(
        message="Retrieved country blacklist",
        status="success",
        data=data,
        status_code=status.HTTP_200_OK,
    )


@country_blacklist_router.post(
    "/countries/add",
    status_code=status.HTTP_201_CREATED,
    response_model=CountryBlacklistResponse,
)
def blacklist_a_country(
    data: CountryBlacklistRequest,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """GeoIP blacklist a country, blocking all access request from that region"""

    try:
        c_name, c_code = country_blacklist_service.add_country_to_blacklist(
            db=db, country_code=data.country_code, reason=data.reason, admin=superadmin
        )
    except HTTPException as exc:
        return JsonResponseDict(
            message=exc.detail, status_code=exc.status_code, status="failed"
        )

    return JsonResponseDict(
        message=f"{c_name} ({c_code.upper()}) successfully added to blacklist.",
        status_code=status.HTTP_201_CREATED,
    )


@country_blacklist_router.delete(
    "/countries/remove/{country_code}", status_code=status.HTTP_200_OK
)
def remove_a_country_from_blacklist(
    data: CountryBlacklistRequest,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """Remove a country from blacklist"""

    c_name, c_code = country_blacklist_service.remove_country_from_blacklist(
        db=db, country_code=data.country_code, reason=data.reason, admin=superadmin
    )

    if not c_name and not c_code:
        return JsonResponseDict(
            message="Country was not in blacklist, no action taken",
            status_code=status.HTTP_200_OK,
        )

    return JsonResponseDict(
        message=f"{c_name} ({c_code.upper()}) successfully removed to blacklist.",
        status_code=status.HTTP_200_OK,
    )


@country_blacklist_router.get("/countries/history", status_code=status.HTTP_200_OK)
def get_blacklist_history(
    country_code: str = Query(
        None,
        max_length=2,
        min_length=2,
        description="iso code of the country to fetch history",
    ),
    superadmin: User = Depends(user_service.get_current_superadmin),
    db: Session = Depends(get_db),
):
    """Retrieve blacklist history"""

    history = country_blacklist_service.fetch_blacklist_history(
        db=db,
        country_code=country_code,
    )

    data = [entry.to_dict() for entry in history]

    return JsonResponseDict(
        message="Retrieved country blacklist history",
        status="success",
        data=data,
        status_code=status.HTTP_200_OK,
    )
