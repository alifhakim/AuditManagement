from datetime import datetime
from audit import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer,primary_key=True)
    username= db.Column(db.String(20),unique=True,nullable=False)
    email= db.Column(db.String(120),unique=True,nullable=False)
    password= db.Column(db.String(60),nullable=False)
    firstName= db.Column(db.String(60),nullable=False)
    lastName= db.Column(db.String(60),nullable=False)
    position= db.Column(db.String(30),nullable=False)
    imageFile= db.Column(db.String(30),nullable=False,default='default.jpg')
    auditReport = db.relationship('Auditreport', backref='auditor', lazy=True)
    risk = db.relationship('Risk', backref='auditor', lazy=True)
    resource = db.relationship('Resource', backref='auditor', lazy=True)
    entityManagement = db.relationship('Entitymanagement', backref='auditor', lazy=True)
    calendar = db.relationship('Calendar',  backref='auditor', lazy=True)
    document = db.relationship('Document',  backref='auditor', lazy=True)

    def __repr__(self):
        return f"{self.firstName} {self.lastName}"

class Calendar(db.Model):
    __tablename__ = 'calendar'

    id = db.Column(db.Integer,primary_key=True)
    eventTitle = db.Column(db.String(120),unique=True,nullable=False)
    startDate = db.Column(db.String(120),nullable=False)    
    endDate = db.Column(db.String(120),nullable=False)    
    guest = db.Column(db.String(120),nullable=False)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # notificationID = db.Column(db.Integer, db.ForeignKey('auditnotification.id'), nullable=False)

    def __repr__(self):
        return f"Calendar('{self.eventTitle}', '{self.guest}')"

class Document(db.Model):
    __tablename__ = 'document'

    id = db.Column(db.Integer,primary_key=True)
    documentTitle = db.Column(db.String(120),unique=True,nullable=False)
    filesDescription = db.Column(db.String(120), nullable=False)
    files= db.Column(db.String(30),nullable=True)
    status = db.Column(db.String(120), nullable=False)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Document('{self.documentTitle}','{self.status}', '{self.files}', '{self.filesDescription}'  )" 
    
class Auditreport(db.Model):
    __tablename__ = 'auditreport'

    id = db.Column(db.Integer,primary_key=True)
    auditReportTitle = db.Column(db.String(120),unique=True,nullable=False)
    auditOwner = db.Column(db.String(120),nullable=False)
    startDate = db.Column(db.String(120),nullable=False)
    scope = db.Column(db.String(225),nullable=False)
    objective = db.Column(db.String(225),nullable=False)
    methodology = db.Column(db.String(225),nullable=False)
    documentType = db.Column(db.String(225),nullable=False)
    description = db.Column(db.Text,nullable=False)
    evidence = db.Column(db.String(120),nullable=True)
    evidenceOwner = db.Column(db.String(120),nullable=False)
    createdAt = db.Column(db.DateTime,nullable=False, default= datetime.now())
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # reportTypeID = db.Column(db.Integer, db.ForeignKey('reporttype.id'), nullable=False)
    # auditNotification = db.relationship('Auditnotification', backref='auditReport', lazy=True)

    def __repr__(self):
        return f"Auditreport('{self.auditReportTitle}', '{self.auditOwner}', '{self.startDate}', '{self.evidence}', '{self.evidenceOwner}', '{self.createdAt}')"
        
class Reporttype(db.Model):
    __tablename__ = 'reporttype'

    id = db.Column(db.Integer,primary_key=True)
    reportTypeName = db.Column(db.String(120),unique=True, nullable=False)
    auditScope = db.Column(db.Text, nullable=False)
    auditMethod = db.Column(db.Text, nullable=False)
    auditObjective = db.Column(db.Text, nullable=False)
    auditSuccessCriteria = db.Column(db.Text, nullable=False)
    # auditReport = db.relationship('Auditreport', backref='reportType', lazy=True)

    def __repr__(self):
        return f"Reporttype('{self.reportTypeName}', '{self.auditScope}', '{self.auditMethod}', '{self.auditObjective}')"

class Risk(db.Model):
    __tablename__ = 'risk'

    id = db.Column(db.Integer,primary_key=True)
    riskName = db.Column(db.String(120),unique=True, nullable=False)
    year = db.Column(db.String(4),nullable=False)
    inherentRisk = db.Column(db.String(120), nullable=False)
    controlRisk = db.Column(db.String(120), nullable=False)
    riskRating = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(120), nullable=False)
    submitDate = db.Column(db.DateTime,nullable=False, default= datetime.now())
    reviewer = db.Column(db.String(120), nullable=False)
    reviewStatus = db.Column(db.String(120), nullable=False)
    filesDescription = db.Column(db.String(120), nullable=False)
    files= db.Column(db.String(30),nullable=True)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    riskprioritization = db.relationship('Riskprioritization', backref='risk', lazy=True)

    def __repr__(self):
        return f"Risk('{self.riskName}', '{self.year}','{self.controlRisk}','{self.inherentRisk}', '{self.status}', '{self.reviewer}', '{self.reviewStatus}', '{self.files}')"


class Riskprioritization(db.Model):
    __tablename__ = 'riskprioritization'

    id = db.Column(db.Integer,primary_key=True)
    riskTitle = db.Column(db.String(120), unique=True, nullable=False)
    riskID = db.Column(db.Integer, db.ForeignKey('risk.id'), nullable=False)

    def __repr__(self):
        return f"Riskprioritization('{self.riskTitle}')"

class Resource(db.Model):
    __tablename__ = 'resource'
    
    id = db.Column(db.Integer,primary_key=True)
    resourceType = db.Column(db.String(120),  nullable=False)
    category = db.Column(db.String(120),  nullable=False)
    description = db.Column(db.String(220),  nullable=False)
    status = db.Column(db.String(120),  nullable=False)
    asset = db.Column(db.String(120), nullable=False)
    assetOwner = db.Column(db.String(120), nullable=False)
    availability = db.Column(db.String(120), nullable=False)
    confidentiality = db.Column(db.String(120), nullable=False)
    filesDescription = db.Column(db.String(120), nullable=False)
    evidence= db.Column(db.String(30),nullable=True)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Resource('{self.category}', '{self.resourceType}'), '{self.description}', {self.status}', '{self.asset}'), '{self.assetOwner}', '{self.availability}'), '{self.confidentiality}','{self.evidence}')" 

class Entitymanagement(db.Model):
    __tablename__ = 'entitymanagement'

    id = db.Column(db.Integer,primary_key=True)
    label = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.String(220), nullable=False)
    entitytype = db.Column(db.String(120), nullable=False)
    auditable = db.Column(db.String(120),  nullable=False)
    status = db.Column(db.String(120),  nullable=False)
    shareScope = db.Column(db.String(120),  nullable=False)
    organization = db.Column(db.String(120),  nullable=False)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # entitytypeID = db.Column(db.Integer, db.ForeignKey('entitytype.id'), nullable=False)


    def __repr__(self):
        return f"Entitymanagement('{self.label}', '{self.schemaStatus}', '{self.auditable}', '{self.status}', '{self.shareScope}', '{self.organization}',, '{self.updateAt}')"

class Entitytype(db.Model):
    __tablename__ = 'entitytype'

    id = db.Column(db.Integer,primary_key=True)
    entityTypeName = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text,  nullable=False)
    Module = db.Column(db.String(120),  nullable=False)
    ownership = db.Column(db.String(120), nullable=False)
    # entityManagement = db.relationship('Entitymanagement', backref='type', lazy=True)

    def __repr__(self):
        return f"Entitytype('{self.entityTypeName}', '{self.description}')"

class Auditmethod(db.Model):
    __tablename__ = 'auditmethod'

    id = db.Column(db.Integer,primary_key=True)
    method = db.Column(db.String(255), unique=True, nullable=False)
    scope = db.Column(db.String(255),  nullable=False)
    documentType = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text,  nullable=False)
    
    def __repr__(self):
        return f"Auditmethod('{self.method}')"

class Methodology(db.Model):
    __tablename__ = 'methodology'

    id = db.Column(db.Integer,primary_key=True)
    scope = db.Column(db.String(120),  nullable=False)
    document = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text,  nullable=False)
    auditmethod_id =db.Column(db.Integer)
    
    def __repr__(self):
        return f"Methodology('{self.scope}')"
