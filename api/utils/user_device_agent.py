from fastapi import Request
from user_agents import parse  # type: ignore
from functools import lru_cache
import logging
import hashlib


logger = logging.getLogger(__name__)


@lru_cache(maxsize=128)
def get_client_ip(request: Request) -> str:
    """
    Get Client user IP
    """
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        # take the first (real client ip)
        ip_list = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]
        if ip_list:
            return ip_list[0]

    # Fall back to direct client IP
    return request.client.host


@lru_cache(maxsize=128)
async def get_device_info(request: Request) -> dict:
    """Retrieves device information from the request headers"""
    try:
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent")
        device_info = parse(user_agent)
        device_name = f"{device_info.device.family} - {device_info.os.family}"
        os_name = device_info.os.family
        os_version = device_info.os.version[:2]
        is_mobile = device_info.is_mobile
        is_tablet = device_info.is_tablet
        is_pc = device_info.is_pc
        is_email_client = device_info.is_email_client
        is_bot = device_info.is_bot

        return {
            "device_name": device_name,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "os_name": os_name,
            "os_version": os_version,
            "is_mobile": is_mobile,
            "is_tablet": is_tablet,
            "is_pc": is_pc,
            "is_email_client": is_email_client,
            "is_bot": is_bot,
        }
    except Exception:
        # log exception
        logger.warning(
            "Error retrieving a client device info, might possibly be an attack attempt",
            exc_info=True,
        )
        return None


@lru_cache(maxsize=128)
def generate_device_fingerprint(user_agent_string: str) -> str:
    """
    Generates a stable fingerprint for a device based on normalized user-agent data.
    Ignores patch-level OS/browser versions to reduce false device differences.

    Returns:
        A SHA-256 hex digest string (64 characters).
    """
    ua = parse(user_agent_string)

    # Normalize OS and browser versions, keep major.minor only
    os_name = ua.os.family or "UnknownOS"
    os_version = ".".join(str(part) for part in ua.os.version[:2]) or "0.0"

    browser_name = ua.browser.family or "UnknownBrowser"
    browser_version = ".".join(str(part) for part in ua.browser.version[:2]) or "0.0"

    device_type = (
        "mobile"
        if ua.is_mobile
        else (
            "tablet"
            if ua.is_tablet
            else "pc" if ua.is_pc else "bot" if ua.is_bot else "unknown"
        )
    )

    raw_fingerprint = f"{os_name.lower()}:{os_version}:{browser_name.lower()}:{browser_version}:{device_type}"

    return hashlib.sha256(raw_fingerprint.encode("utf-8")).hexdigest()
