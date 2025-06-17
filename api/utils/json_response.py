#!/usr/bin/env python3
"""This module contains the Json response class"""
from json import dumps
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from typing import Any, Dict, Optional


class JsonResponseDict(JSONResponse):

    def __init__(
        self,
        message: str,
        status: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        status_code: int = 200,
    ):
        """Initialize your response"""
        self.message = message
        self.data = data
        self.status = status
        self.status_code = status_code
        super().__init__(
            content=jsonable_encoder(self.response()), status_code=status_code
        )

    def __repr__(self):
        return str(
            {
                "message": self.message,
                "data": self.data,
                "status": self.status,
                "status_code": self.status_code,
            }
        )

    def __str__(self):
        """String representation"""
        return dumps(
            {
                "message": self.message,
                "data": self.data,
                "status": self.status,
                "status_code": self.status_code,
            }
        )

    def response(self):
        """Return a json response dictionary"""
        if self.status_code < 300:
            response_dict = {
                "message": self.message,
                "data": self.data,
                "status": self.status or "success",
                "status_code": self.status_code,
            }
            (
                response_dict.pop("data", None)
                if self.data is None or self.data == {}
                else None
            )
            return response_dict

        elif self.status_code == 401:
            response_dict = {
                "message": self.message,
                "data": self.data,
                "status": "unauthorized",
                "status_code": self.status_code,
            }
            response_dict.pop("data", None)
            return response_dict
        elif self.status_code == 409 or 404:
            response_dict = {
                "message": self.message,
                "data": self.data,
                "status": "failed",
                "status_code": self.status_code,
            }
            response_dict.pop("data", None)
            return response_dict

        else:
            response_dict = {
                "message": self.message,
                "data": self.data,
                "status": "error" if self.status == "success" else self.status,
                "status_code": self.status_code,
            }
            response_dict.pop("data", None)
            return response_dict


"""
usage:

return JsonResponseDict(
            message="Job creation successful",
            data={"job": new_job.to_dict()},
            status_code=status.HTTP_201_CREATED
        )
"""
