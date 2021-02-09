from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField,SelectField,RadioField,DateField,DateTimeField
from wtforms.validators import DataRequired,Length,Email,EqualTo, ValidationError
from audit.models import User, Auditreport

class RegistrationForm(FlaskForm):
    firstName = StringField('FirstName',
                           validators=[DataRequired(), Length(min=2, max=20)])
    lastName = StringField('LastName',
                           validators=[DataRequired(), Length(min=2, max=20)])
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    position = SelectField(label='Position', choices=[("Auditor","Auditor"),("Auditee","Auditee"),("Director","Director")])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exist!')

    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exist! please use another Email.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture',
                        validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self,username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already exist!')

    def validate_email(self,email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email already exist! please use another Email.')

class EntityForm(FlaskForm):
    label = StringField('Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    entitytype = StringField('Entity Type', validators=[DataRequired()])
    auditable = SelectField('Auditable',  choices=[("Yes","Yes"),("No","No")])
    status = SelectField('Status',  choices=[("Ongoing","Ongoing"),("Complete","Complete")])
    shareScope = SelectField('Share Scope',  choices=[("Yes","Yes"),("No","No")])
    organization = StringField('Organization', validators=[DataRequired()])
    submit = SubmitField('ADD ENTITY')

class RiskForm(FlaskForm):
    riskName = StringField('Auditable Entity', validators=[DataRequired()])
    year = StringField('Year', validators=[DataRequired()])
    status = SelectField('Overall Status',  choices=[("Pending","Pending"),("Complete","Complete")])
    inherentRisk = SelectField('Inherent Risk',  choices=[("Low","Low"),("High","High")])
    controlRisk = SelectField('Control Risk',  choices=[("Low","Low"),("High","High")])
    riskRating = SelectField('Risk Rating',  choices=[("1","1"),("2","2"),("3","3"),("4","4"),("5","5"),("6","6"),("7","7"),("8","8"),("9","9")])
    reviewer = StringField('Reviewer', validators=[DataRequired()])
    reviewStatus = SelectField('Review Status',  choices=[("Pending","Pending"),("Complete","Complete")])
    files = FileField('Insert evidence',
                            validators=[FileAllowed(['docs', 'docx'])])
    filesDescription = StringField('Description', validators=[DataRequired()])
    submit = SubmitField('ADD RISK')
    
class AuditForm(FlaskForm):
    auditReportTitle = StringField('Title of Audit Program', validators=[DataRequired()])
    auditOwner = StringField('Audit Owner', validators=[DataRequired()])
    startDate = StringField(label="Program Start Date" , validators=[DataRequired()])
    objective = StringField('Audit Objective', validators=[DataRequired()])
    methodology = SelectField('Audit Methodology',choices=[], validators=[DataRequired()])
    scope = StringField('Audit Scope', validators=[DataRequired()])
    documentType = StringField('Document Type', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    evidence = FileField('Evidence',validators=[FileAllowed(['jpg', 'pdf','docx'])])
    evidenceOwner = StringField('Evidence Owner', validators=[DataRequired()])
    submit = SubmitField('ADD AUDIT')

class ResourceForm(FlaskForm):
    resourceType = SelectField(label='Asset Type', choices=[("Physical","Physical"),("Financial","Financial"),("People","People")])
    category = SelectField(label='Category', choices=[("Building","Building"),("Stock","Stock"),("Inventory Equipment","Inventory Equipment"),("Financial Health","Financial Health"),("Cash Flow","Cash Flow"),("Credit","Credit"),("Staff & Resources","Staff & Resources")])
    description = TextAreaField('Description', validators=[DataRequired()])
    status = SelectField(label='Status', choices=[("Pending","Pending"),("Complete","Complete")])
    asset = StringField('Asset', validators=[DataRequired()])
    assetOwner = StringField('Asset Owner', validators=[DataRequired()])
    availability = SelectField(label='Available for Audit', choices=[("Yes","Yes"),("No","No")])
    confidentiality = SelectField(label='Confidentiality', choices=[("High","High"),("Low","Low")])
    evidence = FileField('Insert evidence',
                            validators=[FileAllowed(['docs', 'docx','jpg', 'png'])])
    filesDescription = StringField('Description', validators=[DataRequired()])
    submit = SubmitField('ADD ASSET')

class CalendarForm(FlaskForm):
    eventTitle = StringField('Title of Event', validators=[DataRequired()])
    startDate = StringField('Start Date', validators=[DataRequired()])
    endDate = StringField('End Date', validators=[DataRequired()])
    guest = StringField('Guest', validators=[DataRequired()])
    submit = SubmitField('ADD EVENT')

class DocumentForm(FlaskForm):
    documentTitle = StringField('Title', validators=[DataRequired()])
    filesDescription = StringField('Description', validators=[DataRequired()])
    files = FileField('Upload Engagement Letter',
                            validators=[FileAllowed(['docs', 'docx','jpg', 'png'])])
    status = SelectField(label='Status', choices=[("Pending","Pending")])
    submit = SubmitField('ADD')    