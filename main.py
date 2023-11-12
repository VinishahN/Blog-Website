import flask
from flask import Flask, render_template, redirect, url_for, flash, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from forms import *
from functools import wraps



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # print(type(current_user.get_id()))
        if int(current_user.get_id()) != 1:
            return flask.abort(403)
        return f(*args, **kwargs)
    return decorated_function


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    comments = relationship("Comment", back_populates="comment_author")
    posts = relationship("BlogPost", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    regform = RegisterForm()
    if regform.validate_on_submit():
        email = regform.email.data
        password = regform.password.data
        name = regform.name.data
        user = db.session.query(User).filter(User.email==email).scalar()
        if user:
            flash("You've already signed up with that email, log in instead")
            return redirect(url_for("login"))
        else:
            new_user = User(email=email,
                            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8),
                            name=regform.name.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            print(current_user.name)
            print(current_user.get_id())
            print(current_user.is_authenticated)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=regform, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', "POST"])
def login():
    loginform = LoginForm()
    if loginform.validate_on_submit():
        email = loginform.email.data
        plainpwd = loginform.password.data
        user = db.session.query(User).filter(User.email==email).first()
        print(email)
        if user:
            if check_password_hash(user.password, plainpwd):
                login_user(user)
                print(current_user.name)
                print(current_user.get_id())
                print(current_user.is_authenticated)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect Password. Try again")
                return redirect(url_for("login"))
        else:
            flash("That email id does not exist. Try again")
            return redirect(url_for("login"))
    return render_template("login.html", form=loginform, logged_in=current_user.is_authenticated)

@app.route('/logout')
def logout():
    logout_user()
    print(current_user.is_authenticated)
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = form.comment.data
        if current_user.is_authenticated:
            new_comment = Comment(comment_author = current_user,
                                  parent_post = requested_post,
                                  text = comment)
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            # author=current_user.name,
            author_id = current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_edit=False, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    with app.app_context():
        app.run(debug=True)
