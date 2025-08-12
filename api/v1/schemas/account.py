from pydantic import Field, BaseModel


class AccountReactivationRequest(BaseModel):
    """ """

    email: str = Field(
        ...,
        description="Email of the account to be reactivated",
        examples=["user@auth-system.com"],
    )
