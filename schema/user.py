from mongoengine import *

class User(Document):
    _id = ObjectIdField()
    username = StringField(required=True)
    email = StringField(required=True)
    hashed_password = StringField(required=True)
    disabled = BooleanField(required=True)
    role = StringField(required=True)