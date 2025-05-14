from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class GeoIPResult:
    """Data class to store geolocation information."""

    ip_address: str
    country: str = ""
    region: str = ""
    city: str = ""
    timezone: str = ""
    continent: str = ""
    success: bool = False
    source: str = ""

    def __str__(self) -> str:
        return (
            f"IP: {self.ip_address} | Country: {self.country} | Region: {self.region} | "
            f"City: {self.city} | Timezone: {self.timezone} | Continent: {self.continent} | "
            f"Source: {self.source}"
        )

    def dict(self) -> Dict[str, Any]:
        """Convert the GeoIPResult to a dictionary."""
        return {
            "ip_address": self.ip_address,
            "country": self.country,
            "region": self.region,
            "city": self.city,
            "timezone": self.timezone,
            "continent": self.continent,
            "success": self.success,
            "source": self.source,
        }
