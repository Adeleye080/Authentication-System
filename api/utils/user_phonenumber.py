import httpx
from api.utils.settings import settings


async def get_user_phonenumber_from_user_service(user_email: str) -> str:
    """Retrieves user's phone number from given user service url"""

    service_token = "service-jwt-token"
    headers = {"Authorization": f"Bearer {service_token}"}
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.USER_SERVICE_PHONE_NUMBER_URL}?email={user_email}",
            headers=headers,
        )
        response.raise_for_status()
        return response.json().get("phone_number")
