#!/usr/bin/env python3
"""Password Encryption"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt.gensalt()

    Args:
        password: The password to hash.

    Returns:
        The hashed password.
    """

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates a password using bcrypt.

    Args:
        hashed_password: The hashed password.
        password: The password to validate.

    Returns:
        True if the password is valid, False otherwise.
    """

    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
    except bcrypt.errors.MismatchedHashError:
        return False
