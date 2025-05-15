from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from api.v1.schemas.country_blacklist import CountryBlacklistRequest, CountryBlacklistResponse  # type: ignore
from api.v1.services import user_service
from api.v1.models.user import User
from db.database import get_db


country_blacklist_router = APIRouter(tags=["Country Blacklisting"], prefix="/blacklist")


@country_blacklist_router.get(
    "/all-listed-countries", response_model=list[CountryBlacklistResponse]
)
def get_all_blacklisted_countries(
    superadmin: User = Depends(user_service.get_current_superadmin),
    db: Session = Depends(get_db),
):
    """Get all blacklisted countries."""
    blacklisted_countries = user_service.get_all_blacklisted_countries(db)
    if not blacklisted_countries:
        raise HTTPException(status_code=404, detail="No blacklisted countries found")

    return blacklisted_countries


@country_blacklist_router.post(
    "/blacklist-country",
    status_code=status.HTTP_201_CREATED,
    response_model=CountryBlacklistResponse,
)
def blacklist_a_country(
    data: CountryBlacklistRequest,
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """ """
    return {
        "country": "US",
        "message": "Country blacklisted successfully",
    }


@country_blacklist_router.post(
    "/blacklist-country",
    status_code=status.HTTP_201_CREATED,
)
def blacklist_group_of_countries(
    # data: CountryBlacklistRequest,
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """ """
    pass


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
