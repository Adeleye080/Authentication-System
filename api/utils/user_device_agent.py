from fastapi import Request
from user_agents import parse  # type: ignore
from functools import lru_cache


@lru_cache(maxsize=128)
def get_device_info(request: Request):
    """Retrieves device information from the request headers"""
    user_agent = request.headers.get("User-Agent")
    ip_address = request.client.host
    device_info = parse(user_agent)
    device_name = f"{device_info.device.family} - {device_info.os.family}"  # Example: 'iPhone - iOS'
    return {
        "device_name": device_name,
        "ip_address": ip_address,
        "user_agent": user_agent,
    }
