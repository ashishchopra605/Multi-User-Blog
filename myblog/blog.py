import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'aqiow!1@!dkllfjewlkdlmsdlms2@'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Cookies section


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    """Define functions for rendering Web Pages"""
    def write(self, *a, **kw):
        """Write to Web Page"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Render Jinja template"""
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """Write template to Web Page"""
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """Set Cookie"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Return Cookie Value"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """Set Cookie after Login"""
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """Remove Cookie after Logout"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """Initialise Web Page with signed-in user"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
    """Redirect to front page """
    def get(self):
        self.redirect('/blog')

# Password hashing salting section


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    """Stores User Information """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    """Stores Posts Information """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user_posted = db.StringProperty(required=True)
    likes = db.IntegerProperty(default=0)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class comment(db.Model):
    """Stores Comment Information """
    comment_id = db.IntegerProperty(required=True)
    content = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class PostComment(BlogHandler):
    """Handler for PostComment"""
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            self.render('postcomment.html', p=post, comment="")
        else:
            self.redirect('/signup')

    def post(self, post_id):
        if self.user:
            username = self.user.name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            content = self.request.get('content')
            print content
            if content:
                c = comment(comment_id=int(post_id), content=content,
                            author=username)
                c.put()
            time.sleep(0.1)
            self.redirect("/blog")
        else:
            self.redirect('/signup')


class DeleteComment(BlogHandler):
    """Handler for DeleteComment"""
    def post(self, comment_id):
        if self.user:
            username = self.user.name
            commentobj = comment.get_by_id(int(comment_id))
            if commentobj and commentobj.author == username:
                commentobj.delete()
                time.sleep(0.1)
                self.redirect('/blog')
            else:
                error = "You can't delete others comments"
                self.render("error.html", error=error)
        else:
            self.redirect('/signup')


class EditComment(BlogHandler):
    """Handler for EditComment"""
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            commentobj = comment.get_by_id(int(comment_id))
            if commentobj.author == self.user.name:
                self.render('editcomment.html', p=post, comment=commentobj)
            else:
                error = "You can't edit others comments"
                self.render("error.html", error=error)
        else:
            self.redirect('/signup')

    def post(self, post_id, comment_id):
        content = self.request.get("content")
        username = self.user.name
        commentobj = comment.get_by_id(int(comment_id))
        if commentobj.author == self.user.name:
            commentobj.content = content
            commentobj.put()
            time.sleep(0.1)
            self.redirect('/blog')
        else:
            error = "You can't edit others comments"
            self.render("error.html", error=error)


class Like(db.Model):
    """Stores Like Information """
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)


class LikeHandler(BlogHandler):
    """Handler for Like"""
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            idpost = post.key().id()
            idpost = int(idpost)
            if not post.user_posted == self.user.name:
                likeobj = Like.all()
                likeobj.filter('post_id =', idpost)
                likeobj.filter('user_id =', self.user.key().id())
                result = likeobj.get()
                if result:
                    result.delete()
                    post.likes -= 1
                    post.put()
                    time.sleep(0.1)
                    self.redirect('/blog')
                else:
                    likeobj = Like(post_id=idpost,
                                   user_id=self.user.key().id())
                    likeobj.put()
                    post.likes += 1
                    post.put()
                    time.sleep(0.1)
                    self.redirect('/blog')
            else:
                error = "you cannot like your own post"
                self.render("error.html", error=error)
        else:
            self.redirect("/signup")


class EditPost(BlogHandler):
    """Handler for EditPost"""
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_posted == self.user.name:
                self.render("editpost.html", subject=post.subject,
                            content=post.content, user_posted=self.user.name)
            else:
                error = "you can't edit post"
                self.render("error.html", error=error)
        else:
            self.redirect('/signup')

    def post(self, post_id):
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if subject and content:
                if self.user.name == post.user_posted:
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect("/blog/%s" % str(post.key().id()))
                else:
                    error = "you can't edit post"
                    self.render("error.html", error=error)


class DeletePost(BlogHandler):
    """Handler for DeletePost"""
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post and self.user.name == post.user_posted:
                post.delete()
                commentobj = comment.all().filter('comment_id =',
                                                  int(post_id)).get()
                if commentobj:
                    commentobj.delete()
                self.redirect('/blog/user')
            else:
                error = "you can't delete post"
                self.render("error.html", error=error)


class BlogFront(BlogHandler):
    """Handler for FrontPage"""
    def get(self):
        posts = Post.all().order('-created')
        comments = comment.all().order('-created')
        self.render('front.html', posts=posts, comment=comments)


class PostPage(BlogHandler):
    """Handler after Posting Posts """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        comments = comment.all().filter('post_id =', post_id).order('-created')
        print type(comments)
        self.render("permalink.html", post=post, comment=comments)


class NewPost(BlogHandler):
    """Handler for NewPost"""
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, user_posted=self.user.name)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        user_posted=self.user.name)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    """Check Username"""
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    """Check Password"""
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    """Check Email"""
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    """Handler for Signup"""
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """Register User"""
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/user')


class Login(BlogHandler):
    """Handler for Login"""
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        print u
        if u:
            self.login(u)
            self.redirect('/blog/user')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    """Handler for Logout"""
    def get(self):
        self.logout()
        self.redirect('/signup')


class UserPage(BlogHandler):
    """Handler for UserPage"""
    def get(self):
        if self.user.name:
            username = self.user.name
            posts = Post.all().filter('user_posted =', username)
            self.render('userpage.html', username=username, posts=posts)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/user', UserPage),
                               ('/like/([0-9]+)', LikeHandler),
                               ('/postcomment/([0-9]+)', PostComment),
                               ('/editcomment/([0-9]+)/([0-9]+)', EditComment),
                               ('/deletecomment/([0-9]+)', DeleteComment),
                               ('/editpost/([0-9]+)', EditPost),
                               ('/deletepost/([0-9]+)', DeletePost),
                               ],
                              debug=True)
