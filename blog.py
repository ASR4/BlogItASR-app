import os
import re
import random
import hashlib
import hmac
import json
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):                               #to take in a value and hash it(for the cookie)
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):              #to check if a cookie has not been changed (comaparing the hash value to the already set cookie)
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val    

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self,d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):                 #function to set a cookie, takes in a name and a value
        cookie_val = make_secure_val(val)                   #making a hash of the value
        self.response.headers.add_header(                   #using google app command to set a cookie with name = hashed val and a path(specifying the same path)
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):                     #funtion to get a cookie from the browser
        cookie_val = self.request.cookies.get(name)         #google app command to fetch the cookies by name
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))    #function which invokes set_secure_cookie with the user name

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')   #deleting a cookie by giving the 'user_id' a null value

    def initialize(self, *a, **kw):                         #this is function in google app that gets initialized at every request to
        webapp2.RequestHandler.initialize(self, *a, **kw)   #check if user is logged in or not
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'        

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)        

class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, People!!')

##### user stuff
def make_salt(length = 5):                        #making a random 5 char long string which will be hashed along with the password for better security
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):    #taking a salt, user's name and the password and hashing it together using sha256
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):       #checking if the password entered matches original password
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):          #(not required) for allowing groups
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod              #a decorator function which need not be used as an instance of class User
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key()) #instead of GQL, get_by_id fetches the id of the user from the db

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()   #instead of GQL, gets first instance (specified by .get()) of name from db
        return u

    @classmethod
    def register(cls, name, pw, email = None):  #function that assigns values to variables namely name, password,email
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)           # time date of creation created in db
    last_modified = db.DateTimeProperty(auto_now = True)         # time date of modification created in db

    def render(self):                                             # to create lines
        self._render_text = self.content.replace('\n', '<br>')    # line breaks given by the user to be converted into html form 
                                                                  # to see different lines
        return render_str("post.html", p = self)                 

    def as_dict(self):   # make a dict to convert into json as python does not convert data types it does not know into json
        time_fmt = '%c'  # %c says that represent the time_fmt in a fancy way
        d = {'subject' : self.subject,
             'content' : self.content,
             'created' : self.created.strftime(time_fmt),
             'last_modified' : self.last_modified.strftime(time_fmt)} 
        return d

class BlogFront(BlogHandler):
    def get(self):                                                                     #populates the front page of the blog with 10 recent blogs from the db
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        if self.format == 'html':
            self.render('front.html', posts = posts)
        else:
            return self.render_json([p.as_dict() for p in posts])        
            
class PostPage(BlogHandler):        #permalink handler                                       #this class is to open a particular blog page
    def get(self, post_id):                                             
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())    #it takes in a post_id specified by the user and opens that page if a valid id is given
        post = db.get(key)

        if not post:                                                       #returns an error if the id is not valid
            self.error(404)
            return
        if self.format == 'html':
            self.render("permalink.html", post = post)
        else:
            self.render_json(post.as_dict())                


class NewPost(BlogHandler):
    def get(self):
        if self.user:                       # to check if the user is still logged it(this is invoked by the initialize function)
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)    #from db (through class Post) to the variable p
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)        #after registering this logs in the user
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)   #checks if the user is already registered
        if u:
            self.login(u)                      
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):          #sets cookie to null and redirects to the main page
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:   # to check if the user is still logged it(this is invoked by the initialize function)
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')            

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?(?:\.json)?', BlogFront),
                               ('/blog/([0-9]+)(?:\.json)?', PostPage),   #this is used to pass an id to the Postpage handler
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),                               
                               ],
                              debug=True)
