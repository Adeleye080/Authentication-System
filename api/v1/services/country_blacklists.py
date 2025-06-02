from api.v1.models.country_blacklist import CountryBlacklist, CountryBlacklistHistory
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from api.v1.models.user import User
from typing import Tuple


class CountryBlacklistService:
    """Blacklist service class"""

    def fetch_all(self, db: Session):
        """Fetch all countries in blacklist"""

        blacklisted_countries = db.query(CountryBlacklist).all()
        if len(blacklisted_countries) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No record found"
            )
        return blacklisted_countries

    def add_country_to_blacklist(
        self, db: Session, country_code: str, reason: str, admin: User
    ) -> Tuple[str, str]:
        """
        Adds a country to blacklist
        Returns (country_name, country_code)
        """
        from api.v1.services import geoip_service

        already_blacklisted = (
            db.query(CountryBlacklist)
            .filter(CountryBlacklist.country_code == country_code)
            .first()
        )
        if already_blacklisted:
            raise HTTPException(
                status_code=status.HTTP_200_OK,
                detail="Country already blacklisted.",
            )

        # decipher country name from iso code
        country_name = geoip_service.get_country_name_from_iso_code(
            country_code=country_code
        )

        c_blacklist = CountryBlacklist(
            country_code=country_code, reason=reason, country_name=country_name
        )
        c_blacklist_history = CountryBlacklistHistory(
            country_code=country_code,
            reason=reason,
            country_name=country_name,
            action="Added",
            changed_by=f"superadmin ({admin.email})",
        )

        db.add_all([c_blacklist, c_blacklist_history])
        db.commit()

        return country_name, country_code

    def remove_country_from_blacklist(
        self, db: Session, country_code: str, admin: User
    ):
        """Remove country from blacklist. save the blacklist history."""

        blacklisted_country = (
            db.query(CountryBlacklist)
            .filter(CountryBlacklist.country_code == country_code)
            .first()
        )
        if blacklisted_country:
            c_history = CountryBlacklist(
                country_code=country_code,
                reason=blacklisted_country.reason,
                country_name=blacklisted_country.country_name,
                action="Removed",
                changed_by=f"superadmin ({admin.email})",
            )
            db.delete(blacklisted_country)
            db.add(c_history)
            db.commit()
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Country not found in blacklist",
            )
