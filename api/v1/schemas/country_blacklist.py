from pydantic import BaseModel, Field


class CountryBlacklistRequest(BaseModel):
    """CountryBlacklist model for API request."""

    country_code: str = Field(..., description="Country code (ISO 3166-1 alpha-2)")
    reason: str = Field(
        ..., description="Reason for adding/removing country in blacklist"
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "country_code": "US",
                "reason": "High rate of fraudulent activities or Government ban",
            }
        }


class CountryBlacklistResponse(BaseModel):
    """CountryBlacklist model for API response."""

    country_code: str = Field(..., description="Country code (ISO 3166-1 alpha-2)")
    country_name: str = Field(..., description="The country name")
    reason: str = Field(..., description="Reason for being blacklisted")

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "country": "US",
                "message": "Country blacklisted successfully",
            }
        }
