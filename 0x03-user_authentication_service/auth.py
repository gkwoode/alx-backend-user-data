#!/usr/bin/env python3
"""Authentication of user's credentials"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


def _hash_password(self, password: str) -> bytes:
    """Hash a password
    Args:
        password (str): The password to hash
    Returns:
        bytes: The hashed password
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def _generate_uuid() -> str:
    """Generate a new UUID
    Returns:
        str: A string representation of the new UUID
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user
        Args:
            email (str): The email address of the user
            password (str): The password of the user
        Returns:
            User: The newly created user object
        """
        if self._db.find_user_by(email=email):
            raise ValueError(f"User {email} already exists")

        hashed_password = self._hash_password(password)
        user = self._db.add_user(email=email, hashed_password=hashed_password)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Validate a user login
        Args:
            email (str): The email address of the user
            password (str): The password of the user
        Returns:
            bool: True if the login is valid, False otherwise
        """
        user = self._db.find_user_by(email=email)
        if not user:
            return False
        return bcrypt.checkpw(password.encode(), user.hashed_password)

    def create_session(self, email: str) -> str:
        """Create a new session for a user
        Args:
            email (str): The email address of the user
        Returns:
            str: The new session ID
        """
        user = self._db.find_user_by(email=email)
        if not user:
            raise ValueError(f"User {email} not found")

        session_id = self._generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """Get a user from a session ID
        Args:
            session_id (str): The session ID
        Returns:
            User: The corresponding user, or None if no user is found
        """
        if not session_id:
            return None

        user = self._db.find_user_by(session_id=session_id)
        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroy a user's session
        Args:
            user_id (int): The ID of the user
        Returns:
            None
        """
        user = self._db.find_user_by(id=user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        user.session_id = None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Get a reset password token for a user
        Args:
            email (str): The email address of the user
        Returns:
            str: The reset password token
        """
        user = self._db.find_user_by(email=email)
        if not user:
            raise ValueError(f"User {email} not found")

        token = self._generate_uuid()
        user.reset_token = token
        self._db.update_user(user.id, reset_token=token)
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """Update a user's password
        Args:
            reset_token (str): The reset password token
            password (str): The new password
        Returns:
            None
        """
        user = self._db.find_user_by(reset_token=reset_token)
        if not user:
            raise ValueError(f"Reset password token {reset_token} invalid")

        hashed_password = self._hash_password(password)
        user.hashed_password = hashed_password
        user.reset_token = None
        self._db.update_user(**{
            "id": user.id,
            "hashed_password": hashed_password,
            "reset_token": None,
        })
