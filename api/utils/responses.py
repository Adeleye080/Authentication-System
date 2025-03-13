from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from typing import Any, Dict, Optional


def all_users_response(
    message: str,
    current_page: int,
    per_page: int,
    total: int,
    total_pages: int,
    status_code: int = 200,
    status: str = "success",
    prev_page: str = None,
    next_page: str = None,
    count: int = 0,
    data: Optional[dict] = None,
):
    """
    Json response for all users

    Args:
        :param status_code: int: status code of the response, default to 200
        :param message: str: response message
        :param current_page: int: current page
        :param per_page: int: number of items per page
        :param total: int: total number of items
        :param total_pages: int: total number of pages
        :param status: str: status of the response, default to success
        :param prev_page: str: link to the previous page
        :param next_page: str: link to the next page
        :param count: int: number of items in the current page
        :param data: dict: additional data to be returned

    """

    response_data = {
        "status": status,
        "status_code": status_code,
        "message": message,
        "data": data or {},
        "pagination": {
            "current_page": current_page,
            "per_page": per_page,
            "count": count,
            "total_pages": total_pages,
            "total": total,
            "links": {
                "prev_page": prev_page,
                "next_page": next_page,
            },
        },
    }

    return JSONResponse(
        status_code=status_code, content=jsonable_encoder(response_data)
    )


def auth_response(
    status_code: int, message: str, access_token: str, data: Optional[dict] = None
):
    """Returns a JSON response for successful auth responses"""

    response_data = {
        "status": "success",
        "status_code": status_code,
        "message": message,
        "data": {
            "access_token": access_token,
            **(data or {}),  # Merge additional data if provided
        },
    }

    return JSONResponse(
        status_code=status_code, content=jsonable_encoder(response_data)
    )
