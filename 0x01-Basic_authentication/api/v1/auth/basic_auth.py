#!/usr/bin/env python3
"""Basic Auth"""

import base64
from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """Basic Auth Class"""

    def extract_base64_authorization_header(self,
                                            authorization_header:
                                            str) -> str:
        """Extracts the Base64 part of the
            Authorization header for a Basic Authentication
        Args:
            authorization_header (str): The Authorization header
        Returns:
            str: The Base64 part of the Authorization header
        """

        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """Decodes the Base64 value of a Basic Authentication header
        Args:
            base64_authorization_header (str):
            The Base64 value of the Authorization header
        Returns:
            try: The decoded value of the Authorization header
        """

        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_value = base64.b64decode(base64_authorization_header)
        except binascii.Error:
            return None
        return decoded_value.decode('utf-8')

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """Extracts the user email and password
        from the Base64 decoded value
        Args:
            decoded_base64_authorization_header (str):
            The decoded Base64 value of the Authorization header
        Returns:
            tuple(str, str): The user email and password
        """

        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        email_and_pwd = decoded_base64_authorization_header.replace(":", " ")
        user_email, user_pwd = email_and_pwd.split(' ', 1)
        return user_email, user_pwd

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on his email and password
        Args:
            user_email (str): The user email
            user_pwd (str): The user password
        Returns:
            TypeVar('User'): The User instance
        """

        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search(email=user_email)
        if len(users) == 0:
            return None

        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the User instance for a request
        Args:
            request (Optional[flask.Request]): The request object
        Returns:
            TypeVar('User'): The User instance
        """

        Auth_header = self.authorization_header(request)
        if Auth_header is not None:
            token = self.extract_base64_authorization_header(Auth_header)
            if token is not None:
                decoded = self.decode_base64_authorization_header(token)
                if decoded is not None:
                    email, pword = self.extract_user_credentials(decoded)
                    if email is not None:
                        return self.user_object_from_credentials(email, pword)
        return
