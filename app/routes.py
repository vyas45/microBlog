from flask import render_template,flash, redirect, url_for, request
from werkzeug.urls import url_parse
from app import app
from app.forms import LoginForm
from flask_login import current_user, login_user, logout_user
from flask_login import login_required
from app.models import User
from app import db
from app.forms import RegistrationForm

@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = [
	{
		'author': {'username': 'John'},
		'body': 'Beautiful day in Portland!'
        },
	{
            'author': {'username': 'Susan'},
	    'body': 'The Avengers movie was so cool!'
	}
    ]
    return render_template('index.html', title='Home Page', posts=posts)
#Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        #flash('Login requested for user {}, remember_me={}'.format(form.username.data, form.remember_me.data))
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        '''
            With @login_required to the route the redirect URL would be
            something like : URL /login?next=/index.
            So we try to grab the next page for post login redirection
            If nothing then we fallback to index.html
            An attacker could insert a URL to a malicious site in the next argument, 
            so the application only redirects when the URL is relative, which 
            ensures that the redirect stays within the same site as the application. 
            To determine if the URL is relative or absolute, I parse it with Werkzeug's 
            url_parse() function and then check if the netloc component is set or not.
        '''
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

#Logout
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

#Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    #After validating the form...
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        fmsg = 'Greetings '+ str(user.username) + '!! Welcome to the VyasNet!'
        flash(fmsg)
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)



