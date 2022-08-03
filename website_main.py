'This application runs a server using flask and shows html files. To run type in command line first export FLASK_APP=project name, then flask run'
import json
import os
import re
import logging
import twitter_api
from datetime import datetime
from flask import Flask, redirect, render_template, request, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_login import UserMixin
from passlib.hash import sha256_crypt

#for flask app
APP = Flask(__name__)
LOGIN_MANAGER = LoginManager()
LOGIN_MANAGER.init_app(APP)
LOGIN_MANAGER.login_view = "login"
SECRET_KEY = os.urandom(32)
APP.config['SECRET_KEY'] = SECRET_KEY

#for logger
LOGGER = logging.getLogger('user_login')
LOGGER.setLevel(logging.INFO)
FORMATTER = logging.Formatter(f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
FILER_HANDLER = logging.FileHandler('login.log')
FILER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(FILER_HANDLER)

@APP.route('/')
@login_required
def index():
    '''shows the home page'''
    return render_template('home.html', title='Home page',
                           description='This website has stuff about birds and frogs',
                           nav=nav_list(), time=show_date())

@APP.route('/frogs/')
@login_required
def frogs():
    '''shows a page about frogs'''
    return render_template('frogs.html', title='frogs', nav=nav_list())

@APP.route('/birds')
@login_required
def birds():
    '''shows a page about birds'''
    tweets = twitter_api.get_tweets(twitter_api.science_news)
    return render_template('birds.html', nav=nav_list(), title='birds', tweets=tweets)

def nav_list():
    '''return a list of url's'''
    nav = [
        {'name': 'Home', 'url': '/'},
        {'name': 'Frogs', 'url': '/frogs/'},
        {'name': 'Birds', 'url': '/birds'},
        {'name': 'logout', 'url': '/logout'},
        {'name': 'Change Password', 'url': '/changePassword'}
    ]
    return nav

def show_date():
    '''returns a formated date string'''
    now = datetime.now()
    return now.strftime("%A, %d %B, %Y at %X")

@APP.route('/register', methods=['POST', 'GET'])
def register():
    '''for account registration'''
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        if not check_user_exists(request.form['uname']):
            if valid_pass(request.form['pass']):
                password = hash_pass(str(request.form['pass']))
                new_user = {'name' : str(request.form['uname']), 'password' : password}
                add_user(new_user)
                return redirect(url_for('login'))
            error = 'Password must be at least 12 characters, have at least 1 upper and lower case letter, 1 number, and 1 special character'
        else:
            error = 'Username already taken'
    return render_template('register.html', error=error)

@APP.route('/login', methods=['GET', 'POST'])
def login():
    '''route for login page'''
    error = None
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        if check_user_exists(request.form['uname']):
            if match_pass(request.form['pass'], request.form['uname']):
                user = User(str(request.form['uname']))
                login_user(user)
                next = request.args.get("next")
                return redirect(next or url_for('index'))
            error = 'Incorrect password'
            LOGGER.info('Failed login attempt, IP: %s', request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr))
        else:
            error = 'Username or password is incorrect'
            LOGGER.info('Failed login attempt, IP: %s', request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr))
    return render_template('login.html', error=error)

@APP.route('/changePassword', methods=['GET', 'POST'])
@login_required
def change_password():
    '''change user password'''
    error = None
    success = None
    if request.method == 'POST':
        if valid_pass(request.form['pass']):
            change_pass(request.form['pass'], current_user.name)
            success = 'Your password has been changed'
        elif common_pass(request.form['pass']):
            error = 'This password is unsafe because it is common. Please choose a different password.'
            error += 'Password must be at least 12 characters, have at least 1 upper and lower case letter, 1 number, and 1 special character'
        else:
            error = 'Password must be at least 12 characters, have at least 1 upper and lower case letter, 1 number, and 1 special character'

    return render_template('changePass.html', error=error, success=success)

@APP.route("/logout")
@login_required
def logout():
    '''log out user'''
    logout_user()
    return redirect(url_for('login'))

class User(UserMixin):
    '''required class for login manager for users'''
    def __init__(self, name):
        self.name = name
        self.id = name
    def get_id(self):
        return self.id

@LOGIN_MANAGER.user_loader
def load_user(user_id):
    '''function for login manager'''
    return User(user_id)

def add_user(new_user):
    '''add a user after user information has been validated as a dictionary object'''
    try:
        with open('users.json', 'r+') as data:
            users = json.load(data)
            users["Users"].append(new_user)
            data.seek(0)
            json.dump(users, data, indent=4)
    except IOError:
        print("Could not read file: users.json")

def valid_pass(password):
    '''check input from get_password().
    Must have at least 1 uppercase and lowercase letter,
    1 number, 1 special char, and at least 12 in length'''
    reg = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{12,60}$'
    match_re = re.compile(reg)
    res = re.search(match_re, password)

    if res:
        return True
    return False

def hash_pass(password):
    '''returns a hashed password'''
    return sha256_crypt.hash(password)

def match_pass(given_password, name):
    '''checks to see if a password matches'''
    try:
        with open('users.json', 'r+') as data:
            users = json.load(data)
            for i in users["Users"]:
                if i["name"] == name:
                    return sha256_crypt.verify(given_password, i["password"])
    except IOError:
        print("Could not read file: users.json")
        return False
    return False

def change_pass(given_password, name):
    '''checks to see if a password matches'''
    count = -1
    try:
        with open('users.json', 'r+') as data:
            users = json.load(data)
            for i in users["Users"]:
                count += 1
                if i["name"] == name:
                    new_pass = hash_pass(given_password)
                    users["Users"][count]["password"] = new_pass
                    data.seek(0)
                    json.dump(users, data, indent=4)
                    data.truncate()
                    return True
    except IOError:
        print("Could not read file: users.json")
        return False
    return False

def common_pass(given_password):
    '''Checks if password is common'''
    try:
        with open('commonPassword.txt') as data:
            passwords = data.readlines()
            for i in passwords:
                if given_password == i.strip():
                    return True
            return False
    except IOError:
        print("Could not open file commonPassword.txt")
        return False

def check_user_exists(potential_user):
    '''Check if a username is already in the database'''
    try:
        with open('users.json', 'r+') as data:
            users = json.load(data)
            for i in users["Users"]:
                if i["name"] == potential_user:
                    return True
            return False
    except IOError:
        print("Could not read file: users.json")
