#!/usr/bin/env python3
"""Manage the API authentication"""

from flask import request
from typing import List


class Auth:
    """Ath class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Define which routes don't need authentication"""

        if path in excluded_paths:
            return False

        for excluded_path in excluded_paths:
            if excluded_path.endswith("*"):
                if path.startswith(excluded_path[:-1]):
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """ Request validation!"""
        if request is None:
            return None
        elif 'Authorization' not in request.headers:
            return None
        else:
            return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        return None
