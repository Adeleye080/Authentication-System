from pydantic import BaseModel, Field


class CountryBlacklistRequest(BaseModel):
    """CountryBlacklist model for API request."""

    country: str = Field(..., description="Country code (ISO 3166-1 alpha-2)")
    reason: str = Field(..., description="Reason for blacklisting the country")

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "country": "US",
                "reason": "High rate of fraudulent activities or Government ban",
            }
        }


class CountryBlacklistResponse(BaseModel):
    """CountryBlacklist model for API response."""

    country: str = Field(..., description="Country code (ISO 3166-1 alpha-2)")
    message: str = Field(
        ..., description="Message indicating the status of the operation"
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "country": "US",
                "message": "Country blacklisted successfully",
            }
        }
