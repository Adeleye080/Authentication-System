from pydantic import BaseModel, Field
from typing import Annotated

class TOTPTokenSchema(BaseModel):
    """Schema for validating TOTP token provided by the user"""
    
    totp_token: Annotated[str, Field(min_length=6, max_length=6)]

    @classmethod
    def validate_totp_code(cls, code: str) -> bool:
        """Validates that the TOTP code is a 6-digit number"""
        
        if not code or len(code) != 6:
            return False
        try:
            int(code)
            return True
        except ValueError:
            return False