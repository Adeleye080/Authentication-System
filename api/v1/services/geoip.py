import geoip2.database  # type: ignore
import requests
import logging
import functools
import re
from typing import Callable, List, TypeVar, cast
import datetime
from api.v1.models.geoip_result import GeoIPResult
from api.utils.settings import settings
import pycountry_convert as pc  # type: ignore


logger = logging.getLogger(__name__)

# Type variables for function decorators
F = TypeVar("F", bound=Callable)


class GeoIPService:
    """Class to handle geolocation services."""

    def __init__(self):
        self._maxmind_mmdb_database_path = settings.MAXMIND_MMDB_DATABASE_PATH

    def get_geolocation(self, ip_address: str) -> GeoIPResult:
        """
        Get geolocation data for a given IP address.

        Args:
            ip_address: The IP address to look up

        Returns:
            GeoIPResult object with geolocation data
        """
        # Try MaxMind database first
        if self._maxmind_mmdb_database_path:
            result = self._get_geolocation_from_maxmind(ip_address)
            if result.success:
                return result

        # If MaxMind database fails, try fallback APIs
        return self._get_geolocation_from_apis(ip_address)

    def get_continent_from_country_code(self, country_code: str):
        """
        Get the continent name for a given country code.
        Args:
            country_code: The ISO Alpha-2 country code
        """

        try:
            # Convert ISO Alpha-2 country code to continent code
            continent_code = pc.country_alpha2_to_continent_code(country_code.upper())

            # Convert continent code to full name
            continent_name = pc.convert_continent_code_to_continent_name(continent_code)

            return continent_name
        except Exception as e:
            return f"Error: {str(e)}"

    def get_continent_code_from_country_code(self, country_code: str):
        """
        Get the continent code for a given country code.
        """
        try:
            # Convert ISO Alpha-2 country code to continent code
            continent_code = pc.country_alpha2_to_continent_code(country_code.upper())
            return continent_code
        except Exception as e:
            return f"Error: {str(e)}"

    def api_fallback(self, apis: List[str]) -> Callable[[F], F]:
        """
        Decorator that provides API fallbacks when the decorated function fails.

        Args:
            apis: List of API endpoints to try as fallbacks
        """

        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(ip_address: str) -> GeoIPResult:
                # Try the original function (MaxMind database)
                try:
                    result = func(ip_address)
                    if result.success:
                        return result
                except Exception as e:
                    logger.error(f"MaxMind lookup failed: {str(e)}")

                # If the original function failed, try each fallback API in order
                for api in apis:
                    try:
                        if api == "ip-api.com":
                            result = self.get_geolocation_from_ip_api(ip_address)
                        elif api == "ipwho.is":
                            result = self.get_geolocation_from_ipwhois(ip_address)
                        elif api == "ipapi.co":
                            result = self.get_geolocation_from_ipapi(ip_address)
                        else:
                            continue

                        if result.success:
                            if result.timezone:
                                result.timezone = self.normalize_timezone_offset(
                                    result.timezone
                                )
                            return result
                    except Exception as e:
                        logger.error(f"API {api} failed: {str(e)}")
                        continue

                # If all APIs failed, return a failed result
                return GeoIPResult(
                    ip_address=ip_address, success=False, source="all_failed"
                )

            return cast(F, wrapper)

        return decorator

    def get_geolocation_from_ip_api(self, ip_address: str) -> GeoIPResult:
        """
        Get geolocation data from ip-api.com.

        Args:
            ip_address: The IP address to look up

        Returns:
            GeoIPResult object with geolocation data
        """
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            raise Exception(f"ip-api.com returned status code {response.status_code}")

        data = response.json()

        if data.get("status") != "success":
            raise Exception(
                f"ip-api.com returned error: {data.get('message', 'Unknown error')}"
            )

        return GeoIPResult(
            ip_address=ip_address,
            country_name=data.get("country", ""),
            country_code=data.get("countryCode", ""),
            region=data.get("regionName", ""),
            city=data.get("city", ""),
            timezone=data.get("timezone", ""),
            continent_name=self.get_continent_from_country_code(
                data.get("countryCode", "")
            ),
            continent_code=self.get_continent_code_from_country_code(
                data.get("countryCode", "")
            ),
            success=True,
            source="ip-api.com",
        )

    def get_geolocation_from_ipwhois(ip_address: str) -> GeoIPResult:
        """
        Get geolocation data from ipwho.is.

        Args:
            ip_address: The IP address to look up

        Returns:
            GeoIPResult object with geolocation data
        """
        url = f"https://ipwho.is/{ip_address}"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            raise Exception(f"ipwho.is returned status code {response.status_code}")

        data = response.json()

        if not data.get("success", True):
            raise Exception(
                f"ipwho.is returned error: {data.get('message', 'Unknown error')}"
            )

        return GeoIPResult(
            ip_address=ip_address,
            country_name=data.get("country", ""),
            country_code=data.get("country_code", ""),
            region=data.get("region", ""),
            city=data.get("city", ""),
            timezone=data.get("timezone", {}).get("id", ""),
            continent_name=data.get("continent", ""),
            continent_code=data.get("continent_code", ""),
            success=True,
            source="ipwho.is",
        )

    def get_geolocation_from_ipapi(self, ip_address: str) -> GeoIPResult:
        """
        Get geolocation data from ipapi.co.

        Args:
            ip_address: The IP address to look up

        Returns:
            GeoIPResult object with geolocation data
        """
        url = f"https://ipapi.co/{ip_address}/json/"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            raise Exception(f"ipapi.co returned status code {response.status_code}")

        data = response.json()

        if data.get("error", False):
            raise Exception(
                f"ipapi.co returned error: {data.get('reason', 'Unknown error')}"
            )

        return GeoIPResult(
            ip_address=ip_address,
            country_name=data.get("country_name", ""),
            country_code=data.get("country_code", ""),
            region=data.get("region", ""),
            city=data.get("city", ""),
            timezone=data.get("timezone", ""),
            continent_name=self.get_continent_from_country_code(
                data.get("country", "")
            ),
            continent_code=self.get_continent_code_from_country_code(
                data.get("country", "")
            ),
            success=True,
            source="ipapi.co",
        )

    def normalize_timezone_offset(self, timezone: str) -> str:
        """
        Attempt to convert timezone strings to a standardized format.
        Handles both offset formats (UTC+1) and IANA timezone names (Africa/Lagos).

        Args:
            timezone: The timezone string to normalize

        Returns:
            Normalized timezone string
        """
        if not timezone:
            return ""

        # If already in UTC+X format, return as is
        if timezone.startswith("UTC") or re.match(r"[+-]\d{1,2}(:\d{2})?", timezone):
            return timezone

        try:
            # Use the pytz library if available
            import pytz  # type: ignore

            tz = pytz.timezone(timezone)
            offset = tz.utcoffset(datetime.datetime.now())
            if offset is None:
                return timezone

            hours, remainder = divmod(int(offset.total_seconds()), 3600)
            minutes, _ = divmod(remainder, 60)

            sign = "+" if hours >= 0 else "-"
            return f"UTC{sign}{abs(hours):02d}:{minutes:02d}"
        except Exception:
            # If pytz is not available or timezone is invalid, return as is
            return timezone

    @api_fallback(["ip-api.com", "ipwho.is", "ipapi.co"])
    def get_geolocation_from_maxmind(self, ip_address: str) -> GeoIPResult:
        """
        Get geolocation data from MaxMind GeoIP database.

        Args:
            ip_address: The IP address to look up

        Returns:
            GeoIPResult object with geolocation data
        """

        try:
            # Open the city database
            with geoip2.database.Reader(
                self._maxmind_mmdb_database_path
            ) as city_reader:
                city_response = city_reader.city(ip_address)

                # Extract data from the response
                result = GeoIPResult(
                    ip_address=ip_address,
                    country=city_response.country.name or "",
                    region=(
                        city_response.subdivisions.most_specific.name
                        if city_response.subdivisions
                        else ""
                    ),
                    city=city_response.city.name or "",
                    timezone=city_response.location.time_zone or "",
                    continent=city_response.continent.name or "",
                    success=True,
                    source="maxmind",
                )

                # Normalize timezone if present
                if result.timezone:
                    result.timezone = self.normalize_timezone_offset(result.timezone)

                return result
        except geoip2.errors.AddressNotFoundError:
            raise Exception(f"IP address {ip_address} not found in MaxMind database")
        except Exception as e:
            raise Exception(f"Error querying MaxMind database: {str(e)}")

    def get_ip_geolocation(self, ip_address: str) -> GeoIPResult:
        """
        Get geolocation data for an IP address using MaxMind database with API fallbacks.\n
        Use this as the main entry point for geolocation lookups.
        This method will first attempt to use the MaxMind database, and if that fails, it will fall back to the API.

        Args:
            ip_address: The IP address to look up

        Returns:
            GeoIPResult object with geolocation data
        """
        return self.get_geolocation_from_maxmind(ip_address)
