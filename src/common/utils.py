import re
from passlib.hash import pbkdf2_sha512


class Utils:

    @staticmethod
    def email_is_valid(email):
        email_address_matcher = re.compile("^[a-z]+[\w.-]+@([\w-]+\.)+[\w]+$")
        return True if email_address_matcher.match(email) else False

    @staticmethod
    def hash_password(password):
        return pbkdf2_sha512.encrypt(password)

    @staticmethod
    def check_hashed_password(password, hashed_password):
        '''
        Checks that the password user sent matches that of the database
        :param password: sha512-hashed password
        :param hashed_password: pbkdf2-sha512 encrypted password
        :return: True if password match, False otherwise
        '''
        return pbkdf2_sha512.verify(password, hashed_password)