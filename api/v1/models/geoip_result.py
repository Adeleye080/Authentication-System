from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class GeoIPResult:
    """Data class to store geolocation information."""

    ip_address: str
    country_name: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    timezone: str = ""
    continent_code: str = ""
    continent_name: str = ""
    success: bool = False
    source: str = ""

    def __str__(self) -> str:
        return (
            f"IP: {self.ip_address} | Country: {self.country_name} | Region: {self.region} | "
            f"City: {self.city} | Timezone: {self.timezone} | Continent: {self.continent_name} | "
            f"Source: {self.source}"
        )

    def dict(self) -> Dict[str, Any]:
        """Convert the GeoIPResult to a dictionary."""
        return {
            "ip_address": self.ip_address,
            "country_name": self.country_name,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "timezone": self.timezone,
            "continent_name": self.continent_name,
            "continent_code": self.continent_code,
            "success": self.success,
            "source": self.source,
        }
