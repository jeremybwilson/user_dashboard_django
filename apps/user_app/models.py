# -*- coding: utf-8 -*-
from __future__ import unicode_literals


from django.db import models
import re, bcrypt

# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# Create your models here.

class BlogManager(models.Manager):
    def basic_validator(self, form_data):
        errors = []
        first_name = form_data['first_name']
        last_name = form_data['last_name']
        email = form_data['email']
        password = form_data['password']
        confirm_password = form_data['confirm_password']

        if len(first_name) < 1:
            errors.append('First name field cannot be empty')
        if len(first_name) < 3:
            errors.append('First name field must be longer than 3 characters')
        if len(last_name) < 1:
            errors.append('Last name field cannot be empty')
        if len(last_name) < 3:
            errors.append('Last name field must be longer than 3 characters')
        if len(password) < 1:
            errors.append('Password cannot be empty')
        if len(email) < 1:
            errors.append('Email field cannot be empty')
        if not re.match(EMAIL_REGEX, email):
            errors.append('Email is not valid')
        if len(password) < 4:
            errors.append('Password must be longer than three characters')
        if password != confirm_password:
            errors.append('Passwords must match')

        # for user in User.objects.filter(email=email):
        #   if user:
        #     errors.append('The email already exists. Please use a different one.')
        email_list = User.objects.filter(email=email)

        if len(email_list) > 0:
            errors.append('Account already in use.  Please choose another.')
        try:
            user = User.objects.get(email=email)
            errors.append('Email already in use.  Please choose another')
            return (False, errors)
        except:
            if len(errors) > 0:
                return (False, errors)
            else:
                # REMEMBER TO HASH THE PASSWORD
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                user = User.objects.create(first_name=first_name, last_name=last_name, email=email, pw_hash=pw_hash)
                return (True, user.id)
        return (True, user.id)
        # return errors

    def message_validator(self, form_data):
        errors = []
        message = form_data['message']

        if len(message) < 10:
            errors.append('Messages must be at least ten characters in length.')

        message_list = Message.objects.filter(message=message)

        if len(message_list) > 0:
            errors.append('Error')
        try:
            message = Message.objects.get(message=message)
            errors.append('Error')
            return (False, errors)
        except:
            if len(errors) > 0:
                return (False, errors)
            else:
                message = Message.objects.create(message=message)
                return (True, message.id)
        return (True, message.id)

    def password_validator(self, form_data):
        errors = []
        email = form_data['email']
        password = form_data['password']
        confirm_password = form_data['confirm_password']
            
        if len(password) < 4:
            errors.append('Password must be longer than three characters.')
        if password != confirm_password:
            errors.append('Passwords did not match.  Passwords must match.')

        try:
            user = User.objects.get(email=email)
            # check to see if passwords match
            if not bcrypt.checkpw(password.encode(), user.pw_hash.encode()):
                errors.append('Email or password is invalid')
                return (False, errors)
            return (True, user.id)
        except:
            errors.append('Email or password is invalid')
            return (False, errors)
        # return errors

    def delete_user_by_id(self, user_id):
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return True
        except:
            return False

class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    pw_hash = models.CharField(max_length=500)
    # For permission level, admin is 1 and non-admin is 2.
    permission_level = models.IntegerField(default=2)
    description = models.TextField(default='description')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = BlogManager()

def __str__(self):
    output = "<User object: {} {} {}>".format(self.first_name, self.last_name, self.email, self.permission_level)
    # output = "<User object: {}>".format(self.username)
    return self.output

class Message(models.Model):
    message = models.TextField()
    message_author = models.ForeignKey(User, related_name='messages_of_author')
    message_receiver = models.ForeignKey(User, related_name='messages_of_receiver', default=1)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    objects = BlogManager()

def __str__(self):
    output = "<Message object: {} {} {}>".format(self.message, self.message_author, self.message_receiver)
    # output = "<User object: {}>".format(self.username)
    return self.output

class Comment(models.Model):
    comment = models.TextField()
    comment_author = models.ForeignKey(User, related_name='comments')
    comment_message = models.ForeignKey(Message, related_name='comments')
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    objects = BlogManager()

def __str__(self):
    output = "<Comment object: {} {} {}>".format(self.comment, self.comment_author, self.comment_message)
    # output = "<User object: {}>".format(self.username)
    return self.output