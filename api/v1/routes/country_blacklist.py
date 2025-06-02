from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from api.v1.schemas.country_blacklist import CountryBlacklistRequest, CountryBlacklistResponse  # type: ignore
from api.v1.services import user_service, country_blacklist_service
from api.v1.models.user import User
from db.database import get_db
from api.utils.json_response import JsonResponseDict


country_blacklist_router = APIRouter(tags=["Country Blacklisting"], prefix="/blacklist")


@country_blacklist_router.get(
    "/all-listed-countries", response_model=list[CountryBlacklistResponse]
)
def get_all_blacklisted_countries(
    superadmin: User = Depends(user_service.get_current_superadmin),
    db: Session = Depends(get_db),
):
    """Get all blacklisted countries."""

    blacklisted_countries = country_blacklist_service.fetch_all(db)
    return [country.to_dict() for country in blacklisted_countries]


@country_blacklist_router.post(
    "/blacklist-country",
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
        message=f"{c_name} ({c_code}) successfully added to blacklist.",
        status_code=status.HTTP_201_CREATED,
    )


@country_blacklist_router.delete(
    "/unlist-country/{country_code}", status_code=status.HTTP_200_OK
)
def unlist_a_country_from_blacklist(
    country_code: str,
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """ """
    pass


@country_blacklist_router.delete("/unlist-countries", status_code=status.HTTP_200_OK)
def unlist_group_of_countries_from_blacklist(
    country_codes: list[str],
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """ """
    pass
