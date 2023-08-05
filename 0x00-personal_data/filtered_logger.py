#!/usr/bin/env python3
"""Filter_datum function that returns an obfuscated log message"""

import logging
import re
from typing import List
import csv
import mysql.connector
from filtered_logger import RedactingFormatter
from filtered_logger import get_db

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Obfuscate log message by replacing certain field values

    Args:
        fields: a list of strings representing all fields to obfuscate
        redaction: a string representing by what
            he field will be obfuscated
        message: a string representing the log line
        separator: a string representing by which character is
            separating all fields in the log line (message)

    Returns:
        The log message obfuscated.
    """

    regex = rf"({'|'.join(fields)})\s*{separator}"
    obfuscated_message = re.sub(regex, redaction, message)
    return obfuscated_message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: list[str]):
        """Fileds function"""

        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filters values in incoming log records using filter_datum."""

        message = self._format(record)
        record_message = filter_datum(
                                    self.fields,
                                    self.REDACTION,
                                    message,
                                    self.SEPARATOR)
        return record_message


def get_logger():
    """Returns a logging.Logger object."""

    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


def get_db():
    """Returns a connector to the database
        (mysql.connector.connection.MySQLConnection object)."""

    username = os.environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.environ.get("PERSONAL_DATA_DB_NAME")

    conn = mysql.connector.connect(
        user=username, password=password, host=host, database=db_name
    )

    return conn


def main():
    """Retrieves all rows in the users table
    and displays each row under a filtered format.

    Filtered fields:
        name
        email
        phone
        ssn
        password
    """

    logger = get_logger()
    db_conn = get_db()

    cursor = db_conn.cursor()
    cursor.execute("SELECT * FROM users")

    for row in cursor:
        obfuscated_row = {}
        for field in PII_FIELDS:
            obfuscated_row[field] = "*" * len(row[field])

        logger.info(
            '''
            name=%s;
            email=%s;
            phone=%s;
            ssn=%s;
            password=%s;
            ip=%s;
            last_login=%s;
            user_agent=%s
            ''',
            **obfuscated_row,
        )

    db_conn.close()


if __name__ == "__main__":
    main()
