import uuid
from src.common.database import Database
from src.common.utils import Utils
import src.models.users.errors as UserErrors
import src.models.users.constants as UserConstants
from src.models.alerts.alert import Alert


class User:
    def __init__(self, email, password, _id=None):
        self.email = email
        self.password = password
        self._id = uuid.uuid4().hex if _id is None else _id

    def __repr__(self):
        return f'<User {self.email}>'

    @staticmethod
    def is_login_valid(email, password):
        '''
        This method verifies that an email/password is valid or not
        :param email: The user's email
        :param password: A sha512 password
        :return: True if valid, False otherwise
        '''
        user_data = Database.find_one(UserConstants.COLLECTION, {"email": email})
        if user_data:
            if Utils.check_hashed_password(password, user_data['password']):
                raise UserErrors.IncorrectPasswordError('Wrong Password')
        else:
            raise UserErrors.UserNotExistsError('User does not exists')
        return True

    @staticmethod
    def register_user(email, password):
        user_data = Database.find_one(UserConstants.COLLECTION, {"email": email})

        if user_data:
            raise UserErrors.UserNotExistsError("Email already exists")
        if not Utils.email_is_valid(email):
            raise UserErrors.InvalidEmailError("Not valid email")

        User(email, Utils.hash_password(password)).save_to_db()

        return True

    def save_to_db(self):
        Database.insert(UserConstants.COLLECTION, self.json())

    def json(self):
        return {
            "_id": self._id,
            "email": self.email,
            "password": self.password
        }

    @classmethod
    def find_by_email(cls, email):
        return cls(**Database.find_one(UserConstants.COLLECTION, {'email': email}))

    def get_alerts(self):
        return Alert.find_by_user_email(self.email)


