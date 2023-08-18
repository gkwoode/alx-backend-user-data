#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Create new user
        Args:
            email (str): The email address of the user
            hashed_password (str): The hashed password of the user
        Returns:
            User: The newly created user object
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by keyword arguments
        Args:
            **kwargs: The keyword arguments to filter the query by
        Returns:
            User: The first user found, or None if no user was found
        """
        try:
            return self._session.query(User).filter_by(**kwargs).first()
        except NoResultFound:
            return None
        except InvalidRequestError:
            raise ValueError(f"Invalid query arguments: {kwargs}")

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update a user by ID
        Args:
            user_id (int): The ID of the user to update
            **kwargs: The keyword arguments to update the user with
        Returns:
            None
        """
        user = self.find_user_by(id=user_id)
        if not user:
            raise ValueError(f"User with ID: {user_id} not found")

        for key, value in kwargs.items():
            if not hasattr(user, key):
                raise ValueError(f"Invalid attribute {key}")
            setattr(user, key, value)

        self._session.commit()
