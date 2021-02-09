from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_datepicker import datepicker

app = Flask(__name__,template_folder='templates')
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] ='mysql://sql7391735:nCs3QpBbZm@sql7.freemysqlhosting.net/sql7391735'

db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
datepicker(app)
login_manager=LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category  = 'info'

from audit import routes