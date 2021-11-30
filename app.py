from flask import Flask, render_template, url_for, flash, redirect, request, session, logging
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate   
from datetime import datetime
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from passlib.hash import sha256_crypt
import os
import json
from werkzeug.utils import secure_filename
from functools import wraps
from flask_socketio import SocketIO, emit
from flask_mail import Message, Mail
import urllib.parse




##########################  CONFIG  ####################################

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db2.sqlite3'
db = SQLAlchemy(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)
app.config["SECRET_KEY"] = "testing321"

app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = "greenlightv1@gmail.com",
    MAIL_PASSWORD = 'John123#',
))
mail = Mail(app)

app.config['UPLOAD_FOLDER'] = './static/profile_pics'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'JPG', 'PNG'])


############################    MODELS  ##################################

# Likes association table -- associates between users and likes with to columns
likes = db.Table('likes',
                 db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                 db.Column('post_id', db.Integer, db.ForeignKey('post.id'))
                 )


# Likes association table -- associates between users and likes with to columns
followers = db.Table('follows',
                     db.Column('follower_id', db.Integer,
                               db.ForeignKey('user.id'), nullable=True),
                     db.Column('followed_id', db.Integer,
                               db.ForeignKey('user.id'), nullable=True)
                     )


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), default='default.jpg')
    password = db.Column(db.String(64), nullable=False)
    verified = db.Column(db.Integer, default=0, nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    likes = db.relationship('Post', secondary=likes,
                            backref=db.backref('likes', lazy='dynamic'), lazy='dynamic')
    followed = db.relationship('User', secondary=followers,
                               primaryjoin=(followers.c.follower_id == id),
                               secondaryjoin=(followers.c.followed_id == id),
                               backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
    my_notifications = db.relationship('Notification', backref='author',lazy=True)

    def __repr__(self):
        return f"Post ('{self.id}', '{self.date_posted}')"

# Notification model

# 1 - comment, 2-like, 3-retweet 4-follow you
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    postId = db.Column(db.Integer, nullable=False)
    my_user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_C = db.Column(db.Integer, nullable=False)
    typeAct = db.Column(db.Integer, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False,default=datetime.utcnow)
    
# Post model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_posted = db.Column(db.DateTime, nullable=False,
                            default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    retweet = db.Column(db.Integer, default=None, nullable=True, unique=False)
    comment = db.Column(db.Integer, default=None, nullable=True, unique=False)

# # Message model

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1 = db.Column(db.Integer, nullable=False)
    user2 = db.Column(db.Integer, nullable=False)
    messages = db.relationship('SingleMessage', backref='ChatBoth',lazy=True)
class SingleMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    recipient_id = db.Column(db.Integer, nullable=False)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    chatOwner = db.Column(db.Integer,db.ForeignKey('chat.id'))





############################    Email  ##################################



def send_email(user):   
    newe = urllib.parse.quote_plus(user.email,safe='')
    msg = Message()
    msg.subject = "Flask App Password Reset"
    msg.sender = "greenlightv1@gmail.com"
    msg.recipients = [user.email]
    msg.html = render_template('email.html',user=user,token=newe)
    mail.send(msg)


   


##################################  UTILS #####################################

# Check if an user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# Returns current user
def current_user():
    if len(session) > 0:
        return User.query.filter_by(username=session['username']).first()
    else:
        return None


############################    ROUTES  #####################################

# Home route 
@app.route('/home')
def home():
    posts = Post.query.filter_by(comment=None).all()
    follow_suggestions = User.query.all()[0:6]

    # Remove current user from follow suggestions
    if current_user():  # If there is a user in the session
        if current_user() in follow_suggestions:  # If the current user is in the user's follow suggestions
            follow_suggestions.remove(current_user())

    return render_template('home.html', posts=posts, user=current_user(), Post_model=Post, likes=likes, follow_suggestions=follow_suggestions, User=User)


# Home route (following)
@app.route('/home_following')
@is_logged_in
def home_following():
    posts = []
    follow_suggestions = User.query.all()[0:6]

    follows = current_user().followed.all()

    for follow in follows:  # Get all posts by folled accounts
        user_posts = Post.query.filter_by(author=follow)
        posts += user_posts

    posts.sort(key=lambda r: r.date_posted)  # Sorts posts by date

    # Remove current user from follow suggestions
    if current_user():  # If there is a user in the session
        if current_user() in follow_suggestions:  # If the current user is in the user's follow suggestions
            follow_suggestions.remove(current_user())

    return render_template('home.html', posts=posts, user=current_user(), Post_model=Post, likes=likes, follow_suggestions=follow_suggestions, User=User)

@app.route('/notifications')
def notifications():
    my_nof = Notification.query.filter_by(author=current_user())
    return render_template('notifications.html', user=my_nof, dbUser = User, myUser=current_user())

# Single post route
@app.route('/post/<int:id>')
def post(id):
    post = Post.query.filter_by(id=id).first()
    return render_template('post.html', id=id, post=post, Post_model=Post, user=current_user())

# Register form class
class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=1, max=25)])
    email = StringField('Email Address', [validators.Length(min=6, max=120)])
    password = PasswordField('Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Repeat Password')
    


# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():

        # Get form data
        username = form.username.data
        email = form.email.data.lower()
        password = sha256_crypt.encrypt(str(form.password.data))

        # Make user object with form data
        user = User(username=username, email=email, password=password)

        # Add user object to session
        db.session.add(user)

        # Commit session to db
        db.session.commit()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# User login (default page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('logged_in') :
        return redirect(url_for('home'))
    else: 
        if request.method == 'POST':
            # Get form fields
            email = request.form['email'].lower()
            password_candidate = request.form['password']

            # Get user by email
            user = User.query.filter_by(email=email).first()

            # If there is a user with the email 
            if user != None:
                # Get stored hash
                password = user.password

                # If passwords match
                if sha256_crypt.verify(password_candidate, password):
                    # Passed
                    session['logged_in'] = True
                    session['username'] = user.username
                    session['user_id'] = user.id

                    app.logger.info(f'{user.username} LOGGED IN SUCCESSFULLY')
                    flash('You are now logged in', 'success')
                    return redirect(url_for('home'))

                # else if passwords don't match
                else:
                    error = 'Invalid password'
                    return render_template('login.html', error=error)

            # No user with the email
            else:
                error = 'Email not found'
                return render_template('login.html', error=error)

        # GET Request
        return render_template('login.html')

# Forgot Password

@app.route('/forgotpassword', methods=['GET','POST'])
def forgotpassword() : 
    if request.method == 'POST' :
        email = request.form['email'].lower()
        user = User.query.filter_by(email=email).first()
        if user != None:
            emailFound = True
            send_email(user)
            return render_template('forgotpassword.html', email=email, found=emailFound)
        else:  
            emailFound = False
            error = 'Email not found'
            return render_template('forgotpassword.html', error=error, found=emailFound)

    return render_template('forgotpassword.html')

# Handle Email Confirmation

@app.route('/confirm/<token>', methods=['GET','POST'])
def confirm(token):
    email=urllib.parse.unquote(token)
    user = User.query.filter_by(email=email).first()
    if request.method == 'POST' :
        new_password = request.form['password']
        confirm_password = request.form['confirmpass']
        if new_password != confirm_password :
            error = 'Password do not match'
            return render_template('resetpassword.html', error=error)
        else : 
            user.password = sha256_crypt.encrypt(str(new_password))
            db.session.commit()
            return redirect(url_for('login'))

    
    return render_template('resetpassword.html', email=email)


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


    
# Profile route
@app.route('/profile', methods =['GET','POST'])
@is_logged_in
def profile():
    profile_pic = url_for(
        'static', filename='profile_pics/' + current_user().image_file)
    posts = current_user().posts

    follow_history = current_user().followed.all()

    # Remove current user from follow suggestions
    if current_user():  # If there is a user in the session
        if current_user() in follow_history:  # If the current user is in the user's follow suggestions
            follow_history.remove(current_user())
    
    return render_template('profile.html', profile_pic=profile_pic, posts=posts, Post_model=Post, user=current_user())


# Post form class
class PostForm(Form):
    content = StringField('Content', [validators.Length(min=1, max=280)])

# New Post
@app.route('/new_post/', methods=['GET', 'POST'])
@is_logged_in
def new_post():

    form = PostForm(request.form)
    if request.method == 'POST' and form.validate():

        # Get form content
        content = form.content.data

        # Make post object
        post = Post(content=content, author=current_user())

        # Add post to db session
        db.session.add(post)

        # Commit session to db
        db.session.commit()

        flash('Your new post has been created!  😊', 'success')
        return redirect(url_for('home'))

    return render_template('new_post.html', form=form, title='New post')


@app.route('/edit/<int:id>', methods=['GET','POST'])
def editPost(id) :
    post = Post.query.filter_by(id=id).first()
    form = PostForm(request.form)
    if request.method == 'POST' and form.validate():
        content = form.content.data
        post.content = content
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('new_post.html',form=form,title='Edit')

# Like post
@app.route('/like/<id>')
@is_logged_in
def like_post(id):

    post = Post.query.filter_by(id=id).first()

    # If the requested post does not exist
    if post is None:
        flash(f"Post '{id}' not found", 'warning')
        return redirect(url_for('home'))

    # If the user has already liked the post
    if current_user() in post.likes.all():
        post.likes.remove(current_user())
        db.session.commit()
        return redirect(url_for('home', _anchor=id))
    # If the user has not liked the post yet
    else:
        post.likes.append(current_user())
        notification = Notification(postId=id, author=post.author, user_C=current_user().id , typeAct=2)
        db.session.commit()
        return redirect(url_for('home', _anchor=id))


# Split filename into file extension
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Update picture
@app.route('/update_photo', methods=['GET', 'POST'])
@is_logged_in
def update_photo():

    if request.method == 'POST':

        # No file selected
        if 'file' not in request.files:

            flash('No file selected', 'danger')
            return redirect(url_for('update_photo'))

        file = request.files['file']
        # If empty file
        if file.filename == '':

            flash('No file selected', 'danger')
            return redirect(url_for('update_photo'))

        # If there is a file and it is allowed
        if file and allowed_file(file.filename):

            filename = secure_filename(file.filename)

            current_user().image_file = filename
            db.session.commit()

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            flash(
                f'Succesfully changed profile picture to {filename}', 'success')
            return redirect(url_for('profile'))

    return render_template('update_photo.html', user=current_user())


# Search route
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':

        # Get query from form
        query = request.form['search']

        # Search and save posts
        posts = Post.query.filter(
            Post.content.like('%' + query + '%'))

        persons = User.query.filter(User.username.like('%' + query + '%'))

        return render_template('results.html', posts=posts, Post_model=Post, user=current_user(), query=query, User_model=persons)

# Message route
@app.route('/messages', methods= ['GET', 'POST'])
def messa():
    searchChat = Chat.query.filter((Chat.user1==current_user().id) | (Chat.user2==current_user().id))
    if request.method == 'POST' :
        userSend = request.form['userSend']
        bodyGet = request.form['mess']
        userF = User.query.filter_by(username=userSend).first()
        if userF is None:
            return render_template('./message.html', version=False, error=True, myChats=searchChat, myUser=current_user(), allUser=User)
        else :
            searchSpec = Chat.query.filter((Chat.user1==current_user().id) & (Chat.user2==userF.id)).first()
            if searchSpec is None:
                searchSpec = Chat.query.filter((Chat.user1==userF.id) & (Chat.user2==current_user().id)).first()
            if searchSpec is None :
                newChat = Chat(user1=current_user().id, user2=userF.id)
                newMessage = SingleMessage(sender_id=current_user().id, recipient_id=userF.id, body=bodyGet,chatOwner=newChat.id)      
                newChat.messages.append(newMessage)
                db.session.add(newChat)
                db.session.commit()
                notification = Notification(postId=newChat.id, author=userF, user_C=current_user().id , typeAct=4)
                userF.my_notifications.append(notification)
                db.session.commit()
                return render_template('./message.html', version=False, myChats=searchChat, myUser=current_user(), allUser=User, send=True)
            else :
                newMessage = SingleMessage(sender_id=current_user().id, recipient_id=userF.id, body=bodyGet)
                searchSpec.messages.append(newMessage)
                notification = Notification(postId=searchSpec.id, author=userF, user_C=current_user().id , typeAct=4)
                userF.my_notifications.append(notification)
                db.session.commit()
                return render_template('./message.html', version=False, myChats=searchChat, myUser=current_user(), allUser=User, send=True)
    return render_template('./message.html', version=False, myChats=searchChat, myUser=current_user(), allUser=User)

@app.route('/messages/<id>', methods=['GET', 'POST'])
def messawith(id):
    searchChat = Chat.query.filter((Chat.user1==current_user().id) | (Chat.user2==current_user().id))
    thisChat = Chat.query.filter_by(id=id).first()
    if thisChat.user1 == current_user().id :
        userF = User.query.filter_by(id=thisChat.user2).first()
    else :
        userF = User.query.filter_by(id=thisChat.user1).first()
    if request.method == 'POST' : 
        bodyGet = request.form['mess']
        newMessage = SingleMessage(sender_id=current_user().id, recipient_id=userF.id, body=bodyGet)
        thisChat.messages.append(newMessage)
        notification = Notification(postId=thisChat.id, author=userF, user_C=current_user().id , typeAct=4)
        userF.my_notifications.append(notification)
        db.session.commit()
        return render_template('./message.html', version=True, myChats=searchChat, myUser=current_user(), allUser=User, chatChos= thisChat, otherUser=userF)
    return render_template('./message.html', version=True, myChats=searchChat, myUser=current_user(), allUser=User, chatChos= thisChat, otherUser=userF)

# Follow route
@app.route('/follow/<id>')
@is_logged_in
def follow(id):

    # Get current user
    user_following = current_user()
    # Find user being followed by id
    user_followed = User.query.filter_by(id=id).first()

    if user_following == user_followed:

        flash('You cant follow yourself -_-', 'danger')
        return redirect(url_for('home'))

    else:
        # Follow user
        user_following.followed.append(user_followed)

        # Commit to db
        db.session.commit()

        flash(f'Followed {user_followed.username}', 'success')
        return redirect(url_for('home'))


# Unfollow route
@app.route('/unfollow/<id>')
@is_logged_in
def unfollow(id):
    # Get current user
    user_unfollowing = current_user()
    # Get user being unfollowed by id
    user_unfollowed = User.query.filter_by(id=id).first()

    if user_unfollowing == user_unfollowed:

        flash('You cant unfollow yourself -_-', 'danger')
        return redirect(url_for('home'))

    else:
        # Unfollow
        user_unfollowing.followed.remove(user_unfollowed)

        # Commit to db
        db.session.commit()

        flash(f'Unfollowed {user_unfollowed.username}', 'warning')
        return redirect(url_for('home'))


# Repost route
@app.route('/retweet/<id>')
@is_logged_in
def retweet(id):
    re_post = Post.query.filter_by(id=id).first()

    if re_post.retweet != None:
        flash("You can't repost a reposted tweet :(", 'danger')
        return redirect(url_for('home'))

    if Post.query.filter_by(user_id=current_user().id).filter_by(retweet=id).all():
        rm_post = Post.query.filter_by(
        user_id=current_user().id).filter_by(retweet=id).first()
        db.session.delete(rm_post)
        db.session.commit()

        flash('Unposted successfully', 'warning')
        return redirect(url_for('home'))

    post = Post(content='', user_id=current_user().id, retweet=id)
    notification = Notification(postId=id, author=re_post.author, user_C=current_user().id , typeAct=3)
    re_post.author.my_notifications.append(notification)

    db.session.add(post)
    db.session.commit()

    flash('Reposted successfully', 'success')
    return redirect(url_for('home'))


# New Comment
@app.route('/new_comment/<post_id>', methods=['GET', 'POST'])
@is_logged_in
def new_comment(post_id):

    # Commented post
    commented_post = Post.query.filter_by(id=post_id).first()

    form = PostForm(request.form)
    if request.method == 'POST' and form.validate():

        # Get form content
        content = f'@{commented_post.author.username}  ' + form.content.data

        notification = Notification(postId=post_id, author=commented_post.author, user_C=current_user().id , typeAct=1)
        
        # Make comment object
        comment = Post(content=content, author=current_user(), comment=post_id)
        commented_post.author.my_notifications.append(notification)
        # Add comment to db session

        db.session.add(comment)

        # Commit session to db
        db.session.commit()

        flash(
            f"You have replied to {commented_post.author.username}'s tweeet", 'success')
        return redirect(url_for('home'))

    return render_template('new_post.html', form=form, title=f"Comment to @{commented_post.author.username}'s post:")


#hadles and shows user there is an error
@app.errorhandler(404)
def error404(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    socketio.run(app, debug=True)
