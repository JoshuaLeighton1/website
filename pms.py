from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
#import necessities

#configure flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Roelf.db'
#configure Bcrypt for passwords later
Bcrypt = Bcrypt(app)
#configure database
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'thisIsTheKey'

#initialize LoginManager() that contains the code that lets the app and Flask work together
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

#create a user loader function
@login_manager.user_loader

def load_user(user_id):
    return User.query.get(int(user_id))
 
#create a User Table in our database using UserMixin
class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)
    #cannot use the same username
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

#create a Registration form for our signup Page using FlaskForm
class RegisterForm(FlaskForm):

    username = StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw ={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")
    #create a function to check if the username already exists
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username= username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one")

#create a LoginForm for our Login page
class LoginForm(FlaskForm):

    username = StringField('Username',validators=[InputRequired(),Length(min=4, max =20)], render_kw ={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(),Length(min=4,max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")
     
#create a projects table in our database
class projects(db.Model):

    proj_num = db.Column(db.Integer, primary_key =True, nullable=False)
    project_name = db.Column(db.String(80), unique = True, nullable=False)
    Typ = db.Column(db.String(90))
    physical_address = db.Column(db.String(90), nullable = False)
    Customer_ID = db.Column(db.String(100), nullable=False)
    Engineer_ID = db.Column(db.String(100), nullable = False)
    Architect_ID = db.Column(db.String(100), nullable=False)
    Manager_ID = db.Column(db.String(100), nullable=False)
    ERF_num = db.Column(db.String(100), nullable = False)
    Total = db.Column(db.Integer, nullable = False)
    Amount_paid = db.Column(db.Integer)
    Deadline = db.Column(db.String(100))
    complete = db.Column(db.String(100))

    def __repr__(self):
        return '<projects %r>' % self.project_name

#create route for index page
@app.route('/')
def index():
    return render_template('index.html')

#create route for dashboard
@app.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

#create route for Login
@app.route('/Login', methods =['GET', 'POST'])
def login():

    form = LoginForm()
    #check if user exists
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if Bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                #open dashboard if username + password successful
                return redirect(url_for('dashboard'))
    #else just render login page
    return render_template('Login.html', form = form)

#create a route for the sign up page
@app.route('/signUp', methods =['GET', 'POST'])
def register():
    
    form = RegisterForm()
    
    if form.validate_on_submit():
        pasw = form.password.data
        hashed_password = Bcrypt.generate_password_hash(pasw).decode('utf-8')
        new_user = User(username= form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/Login')

    return render_template('signUp.html', form = form)

#create a log out route, just redirects to index page
@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('/')

#create a route to register a new project
@app.route('/reg', methods = ['GET', 'POST'])
def reg():
    if request.method == 'POST':
        name = request.form['name']
        number = int(request.form['number'])
        typ = request.form['type']
        address = request.form.get('ad',False)
        custID = request.form['custID']
        engID = request.form['engID']
        archID = request.form['archID']
        manID = request.form['manID']
        erf = request.form['ERF']
        total = request.form['total']
        amount = request.form['amount']
        deadline = request.form['deadline']
        status = request.form['complete']
        new_proj = projects(proj_num = number, project_name = name, Typ = typ, physical_address= address, Customer_ID = custID, Engineer_ID = engID, Architect_ID = archID, Manager_ID = manID, ERF_num = erf, Total = total, Amount_paid = amount, Deadline = deadline, complete = status)
        db.session.add(new_proj)
        db.session.commit()
        #once form is filled redirects to dashboard
        return redirect('dashboard.html')
    return render_template('reg.html')

#create route to edit an existing project
@app.route('/up', methods = ['GET', 'POST', 'DELETE', 'PUT'])
def edit():
    proj = projects.query.all()
    if request.method == "POST":
        numb = int(request.form['number'])
        return render_template('up.html', proj = proj, numb = numb)
    return render_template('up.html')


if __name__ == "__main__":
    app.run(debug=True) 
    
