# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
import bcrypt
from .models import User, Message, Comment
# from .models import *
# from .models import Message
# from .models import Comment

# Create your views here.
def index(request):
    if 'user_id' not in request.session:
        request.session['user_id'] = False
    #     return redirect('users:new')

    if 'logged_in' not in request.session:
        request.session['logged_in'] = False
    #     return redirect('users:new')

    if request.session['logged_in'] != False:
        # find the user id of the logged in user
        user_id = int(request.session['user_id'])
        print "*" * 80
        print "Here is the USER ID from session:", user_id
        # user_list = User.objects.all()
        specific_user = User.objects.get(id=user_id)
        context = {
            'user_data': User.objects.all(),
            'specific_user': specific_user
        }
        return render(request, 'user_app/index.html', context)
    else:
        return render(request, 'user_app/index.html')

def register_page(request):
    # same as the register_page route
    if 'logged_in' not in request.session:
        request.session['logged_in'] = False
    context = {}
    return render(request, 'user_app/register.html', context)

def dashboard(request):
    context = {
        'user_data': User.objects.all(),
        'specific_user': User.objects.get(id=request.session['user_id'])
    }
    return render(request, 'user_app/dashboard.html', context)

def register(request):
    if request.method == 'POST':
        if request.POST['submit'] == 'Register' or request.POST['submit'] == 'Create':
            valid, result = User.objects.basic_validator(request.POST)

            if valid:
                email = request.POST['email']
                # login status & user id => saved to session
                request.session['logged_in'] = True
                request.session['user_id'] = User.objects.get(email=email).id
                user_id = request.session['user_id']
                user_level = User.objects.get(email=email).permission_level

                if 'login_status' not in request.session:
                    request.session['login_status'] = 1
                else:
                    request.session['login_status'] = 1

                if 'user_level' not in request.session:
                    # request.session['id'] = user.id
                    request.session['id'] = user_id
                    request.session['user_level'] = user_level
                    redirect_url = "/users/"+str(user_id)+"/show/"
                    return redirect(redirect_url)

                elif request.session['user_level'] == 2:
                    request.session['id'] = user_id
                    request.session['user_level'] = user_level
                    redirect_url = "/users/"+str(user_id)+"/show/"
                    return redirect(redirect_url)

                elif request.session['user_level'] == 1:
                    redirect_url = "/users/"+str(user_id)+"/show/"
                    return redirect(redirect_url)

            else:
                for error in result:
                    messages.error(request, error)
                return redirect('users:register')

def edit(request, user_id):
    context = {
        'user_data': User.objects.filter(id=user_id)
    }
    return render(request, 'user_app/edit.html', context)

def edit_users(request):
    if request.method == 'POST':
        errors = []
        user = User.objects.get(id=request.POST['id'])
        if request.POST['submit'] == 'Save':
            user.email = request.POST['email']
            user.first_name = request.POST['first_name']
            user.last_name = request.POST['last_name']
            user.user_level = request.POST['user_level']
            user.save()
            return redirect('/dashboard')

        if request.POST['submit'] == 'Update Password':
            errors = User.objects.password_validator(request.POST)
            if len(errors):
                for tag, error in errors.iteritems():
                    messages.error(request, error, extra_tags=tag)
                redirect_url = "/users/"+str(user_id)+"/edit/"
                print "*" * 80
                print redirect_url
                return redirect(redirect_url)

            pw_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            user.pw_hash = pw_hash
            user.save()
            return redirect('/dashboard')

        if request.POST['submit'] == 'Edit Description':
            user.description = request.POST['description']
            user.save()
            return redirect('/dashboard')
    else:
        return redirect('/dashboard')

def login_page(request):
    return render(request, 'user_app/login.html')

def login(request):
    if request.method == 'POST':
        errors = []
        email = request.POST['email']
        password = request.POST['password']
        if request.POST['submit'] == 'Login':
            user = User.objects.filter(email=email)
            if not user:
                messages.add_message(request, messages.INFO, 'User does not exist')
                return redirect('users:signin')
            else:
                for user in user:
                    user_password = user.pw_hash
                    if bcrypt.checkpw(password.encode(), user_password.encode()):
                        context = {
                            'name': user.first_name,
                            'status': 'logged in',
                            'logged_in': True,
                            'email_error': 'User does not exist'
                        }
                        if 'login_status' not in request.session:
                            request.session['login_status'] = 1
                        else:
                            request.session['login_status'] = 1

                        request.session['logged_in'] = True
                        request.session['user_id'] = user.id
                        request.session['user_level'] = user.permission_level
                        redirect_url = "/users/"+str(user.id)+"/show/"
                        return redirect(redirect_url)
                    else:
                        messages.add_message(request, messages.INFO, 'Password is incorrect')
                        return redirect('users:signin')
        else:
            return redirect('users:signin')
    else:
        return redirect('users:index')


def show(request, user_id): # this view is used for the profile page 
    user = User.objects.get(id=user_id)
    messages = user.messages_of_receiver.all()
    context = {
        'user': user,
        'specific_user': user,
        'messages': messages,
    }
    for message in user.messages_of_receiver.all():
        context['message_id'] = message.id
        context['comments'] = message.comments.all()

    return render(request, 'user_app/profile.html', context)


def delete(request, user_id):
    if request.method == 'POST':
        User.objects.delete_user_by_id(user_id)
    return redirect('users:index')

def logout(request):
  request.session.clear()
  return redirect('users:index')

def message(request, user_id):
    if request.method == 'POST':
        author = User.objects.get(id=request.session['user_id'])
        receiver = User.objects.get(id=user_id)
        author.messages_of_author.create(message=request.POST['message'], message_receiver=receiver)
        redirect_url = "/users/"+str(user_id)+"/show/"
        return redirect(redirect_url)

def comment(request, message_id):
    print "*" * 80
    print "Session user_id:", request.session['user_id']

    message = Message.objects.get(id=message_id)
    author = User.objects.get(id=request.session['user_id'])
    message.comments.create(comment=request.POST.get('user_comment', 'default comment'), comment_author=author)
    # str(message.message_receiver.id)
    redirect_url = "/users/"+str(message.message_receiver.id)+"/show/"
    return redirect(redirect_url)