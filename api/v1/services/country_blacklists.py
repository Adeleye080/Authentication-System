from api.v1.models.country_blacklist import CountryBlacklist, CountryBlacklistHistory
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from api.v1.models.user import User
from typing import Tuple, Optional


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

        country_code = country_code.upper()

        already_blacklisted = (
            db.query(CountryBlacklist)
            .filter(CountryBlacklist.country_code == country_code.upper())
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
            country_code=country_code.upper(),
            reason=reason,
            country_name=country_name,
            action="Added",
            changed_by=f"superadmin ({admin.email})",
        )

        db.add_all([c_blacklist, c_blacklist_history])
        db.commit()

        return country_name, country_code

    def remove_country_from_blacklist(
        self, db: Session, country_code: str, reason: str, admin: User
    ) -> Tuple[str, str]:
        """Remove a country from blacklist. save the blacklist history.\n
        Return (Country_name, country_code)"""

        country_code = country_code.upper()

        blacklisted_country = (
            db.query(CountryBlacklist)
            .filter(CountryBlacklist.country_code == country_code)
            .first()
        )
        if blacklisted_country:
            c_history = CountryBlacklistHistory(
                country_code=country_code,
                reason=reason,
                country_name=blacklisted_country.country_name,
                action="Removed",
                changed_by=f"superadmin ({admin.email})",
            )
            db.delete(blacklisted_country)
            db.add(c_history)
            db.commit()
            return blacklisted_country.country_name, blacklisted_country.country_code
        else:
            return None, None

    def bulk_remove_countries_from_blacklist():
        """ """
        pass

    def fetch_blacklist_history(self, db: Session, country_code: Optional[str] = None):
        """
        Retrieve country blacklist history.
        Retrieves all blacklist history if `country_code` is not provided.

        :param [Optional] country_code: Iso code of the country
        """

        if country_code:
            country_code = country_code.upper()
            return (
                db.query(CountryBlacklistHistory)
                .filter(CountryBlacklistHistory.country_code == country_code)
                .order_by(CountryBlacklistHistory.id.desc())
                .all()
            )
        else:
            return (
                db.query(CountryBlacklistHistory)
                .order_by(CountryBlacklistHistory.id.desc())
                .all()
            )
