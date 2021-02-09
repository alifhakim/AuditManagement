import os
import secrets
from PIL import Image
from flask import Flask, send_file, render_template, url_for, flash, redirect, request, abort, jsonify, json, make_response
from audit import app, db, bcrypt
from audit.forms import RegistrationForm, LoginForm, UpdateAccountForm, EntityForm, RiskForm, AuditForm, ResourceForm, CalendarForm, DocumentForm
from audit.models import User, Entitymanagement, Risk, Auditreport, Resource, Calendar, Document, Auditmethod
from flask_login import login_user, current_user, logout_user, login_required


# save profile picture
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

# save files risk
def save_files(form_files):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_files.filename)
    files_fn = random_hex + f_ext
    files_path = os.path.join(app.root_path, 'static/risk_files', files_fn)

    return files_fn

# save files resource
def save_evidence(form_evidence):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_evidence.filename)
    evidence_fn = random_hex + f_ext
    evidence_path = os.path.join(app.root_path, 'static/resource_evidence', evidence_fn)

    return evidence_fn

# save files document
def save_files(form_files):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_files.filename)
    files_fn = random_hex + f_ext
    files_path = os.path.join(app.root_path, 'static/document_files', files_fn)

    return files_fn

@app.route("/")
def home():
    return render_template('home.html')

# setting is for edit account info
@app.route("/setting", methods=['GET', 'POST'])
def setting():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.imageFile = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account have been update!', 'success')
        return redirect(url_for('setting'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    imageFile = url_for('static', filename='profile_pics/' + current_user.imageFile)
    return render_template('setting.html', title='Setting', imageFile=imageFile, form=form)

# main page route setting for web application
@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')

@app.route("/dashboard/riskdata", methods=['GET', 'POST'])
@login_required
def dashboardriskdata():
    risk=Risk.query.all()
    riskArray=[]
    for risk in risk   :
        riskobj={}
        riskobj=risk.status
        riskArray.append(riskobj)
    return jsonify( riskArray)

@app.route("/dashboard/resourcedata", methods=['GET', 'POST'])
@login_required
def dashboardresourcedata():
    resource=Resource.query.all()
    resourceArray=[]
    for resource in resource   :
        resourcekobj={}
        resourceobj=resource.resourceName
        resourceArray.append(resourceobj)
    return jsonify(resourceArray)

@app.route("/dashboard/auditdata", methods=['GET', 'POST'])
@login_required
def dashboardauditdata():
    auditreport = Auditreport.query.all()
    auditArray=[]
    for auditreport in auditreport   :
        auditreportkobj={}
        auditreportobj=auditreport.auditReportTitle
        auditArray.append(auditreportobj)
    return jsonify(auditArray)

# registration page route setting
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8') 
        user = User(username=form.username.data,email=form.email.data,password=hashed_password,firstName=form.firstName.data,lastName=form.lastName.data,position=form.position.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

# login page route setting
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user,remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

#for logout process
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

# for Entity List
@app.route("/entity_list" , methods=['GET', 'POST'])
@login_required
def entity_list():
    entitymanagement=Entitymanagement.query.all()
    return render_template('entity_list.html', title='Entity List', entitymanagement=entitymanagement)

@app.route("/entity_list/create_entity", methods=['GET', 'POST'])
@login_required
def create_entity():
    form = EntityForm()
    if form.validate_on_submit():
        entitymanagement= Entitymanagement(label=form.label.data, description=form.description.data, entitytype=form.entitytype.data, auditable=form.auditable.data, status=form.status.data, shareScope=form.shareScope.data, organization=form.organization.data, auditor=current_user)
        db.session.add(entitymanagement)
        db.session.commit()
        flash('Your entity has been created!', 'success')
        return redirect(url_for('entity_list'))
    return render_template('create_entity.html', title='Create Entity', form=form, legend='New Entity')

@app.route("/entity_list/<int:entitymanagement_id>/update" , methods=['GET', 'POST'])
@login_required
def update_entity(entitymanagement_id):
    entitymanagement = Entitymanagement.query.get_or_404(entitymanagement_id)    
    form = EntityForm()
    if form.validate_on_submit():
        entitymanagement.label = form.label.data
        entitymanagement.description = form.description.data
        entitymanagement.entitytype = form.entitytype.data
        entitymanagement.auditable = form.auditable.data
        entitymanagement.status = form.status.data
        entitymanagement.shareScope = form.shareScope.data
        entitymanagement.organization = form.organization.data
        db.session.commit()
        flash('Your entity has been updated!', 'success')
        return redirect(url_for('entity_list', entitymanagement=entitymanagement))
    elif request.method == 'GET':
        form.label.data = entitymanagement.label
        form.description.data = entitymanagement.description
        form.entitytype.data = entitymanagement.entitytype
        form.auditable.data = entitymanagement.auditable
        form.status.data = entitymanagement.status
        form.shareScope.data = entitymanagement.shareScope
        form.organization.data = entitymanagement.organization
    return render_template('create_entity.html', title='Update Entity', form=form, legend='Update Entity')

@app.route("/entity_list/<int:entitymanagement_id>/delete" , methods=['GET', 'POST'])
@login_required
def delete_entity(entitymanagement_id):
    entitymanagement = Entitymanagement.query.get_or_404(entitymanagement_id)
    db.session.delete(entitymanagement)
    db.session.commit()
    flash('Your entity  has been deleted!', 'success')
    return redirect(url_for('entity_list'))

@app.route("/risk_prioritization" , methods=['GET', 'POST'])
@login_required
def risk_prioritization():
    return render_template('risk_prioritization.html', title='Risk Prioritization')

@app.route("/risk_prioritization/data", methods=['GET', 'POST'])
@login_required
def prioritizationdata():   
    risk=Risk.query.all()
    prioritizationArray=[]
    for risk in risk   :
        riskobj={}
        riskobj1=risk.riskName
        riskobj2=risk.riskRating
        prioritizationArray.append(riskobj1)
        prioritizationArray.append(riskobj2)
    return jsonify(prioritizationArray)

# for Risk List
@app.route("/risk_list" , methods=['GET', 'POST'])
@login_required
def risk_list():
    risk=Risk.query.all()
    return render_template('risk_list.html', title='Risk list', risk=risk)

@app.route("/risk_list/create_risk" , methods=['GET','POST'])
@login_required
def create_risk():
    form = RiskForm()
    if form.validate_on_submit():
        risk= Risk(riskName=form.riskName.data, status=form.status.data, inherentRisk=form.inherentRisk.data, controlRisk=form.controlRisk.data, riskRating=form.riskRating.data,reviewer=form.reviewer.data, reviewStatus=form.reviewStatus.data, files=form.files.data, year=form.year.data, filesDescription=form.filesDescription.data, auditor=current_user)
        if form.files.data:
            files_file = save_files(form.files.data)
            current_user.files = files_file
        db.session.add(risk)
        db.session.commit()
        flash('Your risk has been created!', 'success')
        return redirect(url_for('risk_list'))
    return render_template('create_risk.html', title='Add', form=form)

@app.route("/risk_list/<int:risk_id>/update", methods=['GET','POST'])
@login_required
def update_risk(risk_id):
    risk = Risk.query.get_or_404(risk_id)    
    form = RiskForm()
    if form.validate_on_submit():
        risk.riskName = form.riskName.data
        risk.year = form.year.data
        risk.inherentRisk = form.inherentRisk.data
        risk.controlRisk = form.controlRisk.data
        risk.riskRating = form.riskRating.data
        risk.status = form.status.data
        risk.reviewer = form.reviewer.data
        risk.reviewStatus = form.reviewStatus.data
        risk.filesDescription = form.filesDescription.data
        db.session.commit()
        flash('Your risk has been updated!', 'success')
        return redirect(url_for('risk_list', risk_id=risk.id))
    elif request.method == 'GET':
        form.riskName.data = risk.riskName
        form.year.data = risk.year
        form.inherentRisk.data = risk.inherentRisk
        form.controlRisk.data = risk.controlRisk
        form.riskRating.data = risk.riskRating
        form.status.data = risk.status
        form.reviewer.data = risk.reviewer
        form.reviewStatus.data = risk.reviewStatus
        form.filesDescription.data = risk.filesDescription
    return render_template('create_risk.html', title='Edit', form=form,risk_id=risk.id)

@app.route("/risk_list/<int:risk_id>/delete" , methods=['GET','POST'])
@login_required
def delete_risk(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    db.session.delete(risk)
    db.session.commit()
    flash('Your risk  has been deleted!', 'success')
    return redirect(url_for('risk_list'))

@app.route("/risk_share" , methods=['GET', 'POST'])
@login_required
def risk_share():
    return render_template('risk_share.html', title='Share Risk')
    
# for Audit list
@app.route("/audit_list" , methods=['GET', 'POST'])
@login_required
def audit_list():
    audit=Auditreport.query.all()
    return render_template('audit_list.html', title='Audit List', audit=audit)

@app.route("/audit_list/create_audit", methods=['GET', 'POST'])
@login_required
def create_audit():
    form = AuditForm()
    method= Auditmethod.query.all()
    form.methodology.choices = [(method.method,method.method) for method in Auditmethod.query.all()]    
    if form.validate_on_submit():
        if form.evidence.data:
            evidence_file = save_evidence(form.evidence.data)
            form.evidence.data=evidence_file
        audit= Auditreport(auditReportTitle=form.auditReportTitle.data, auditOwner=form.auditOwner.data, startDate=form.startDate.data, objective=form.objective.data, methodology=form.methodology.data,scope=form.scope.data, documentType=form.documentType.data, description=form.description.data,evidence=form.evidence.data , evidenceOwner=form.evidenceOwner.data, auditor=current_user)
        db.session.add(audit)
        db.session.commit()
        flash('Your audit has been created!', 'success')
        return redirect(url_for('audit_list'))
    return render_template('create_audit.html', title='Create Audit', form=form, legend='New Audit')

@app.route("/audit_list/<int:auditreport_id>/update" , methods=['GET', 'POST'])
@login_required
def update_audit(auditreport_id):
    auditreport = Auditreport.query.get_or_404(auditreport_id)
    form = AuditForm()
    method= Auditmethod.query.all()
    form.methodology.choices = [(method.method,method.method) for method in Auditmethod.query.all()]  
    if form.validate_on_submit():
        if form.evidence.data:
            evidence_file = save_evidence(form.evidence.data)
            form.evidence.data=evidence_file
        auditreport.auditReportTitle = form.auditReportTitle.data
        auditreport.auditOwner = form.auditOwner.data
        auditreport.startDate = form.startDate.data
        auditreport.evidence = form.evidence.data
        auditreport.scope = form.scope.data
        auditreport.objective = form.objective.data
        auditreport.methodology = form.methodology.data
        auditreport.documentType = form.documentType.data
        auditreport.description = form.description.data
        auditreport.evidenceOwner = form.evidenceOwner.data
        db.session.commit()
        flash('Your audit has been updated!', 'success')
        return redirect(url_for('audit_list', auditreport_id=auditreport.id))
    elif request.method == 'GET':
        form.auditReportTitle.data = auditreport.auditReportTitle
        form.auditOwner.data = auditreport.auditOwner
        form.startDate.data = auditreport.startDate
        form.scope.data = auditreport.scope
        form.objective.data = auditreport.objective
        form.methodology.data = auditreport.methodology
        form.documentType.data = auditreport.documentType
        form.description.data = auditreport.description
        form.evidence.data = auditreport.evidence
        form.evidenceOwner.data = auditreport.evidenceOwner
    return render_template('create_audit.html', title='Update Audit', form=form, legend='Update Audit')

@app.route("/audit_list/<int:auditreport_id>/delete" , methods=['GET', 'POST'])
@login_required
def delete_audit(auditreport_id):
    auditreport = Auditreport.query.get_or_404(auditreport_id)
    db.session.delete(auditreport)
    db.session.commit()
    flash('Your audit report  has been deleted!', 'success')
    return redirect(url_for('audit_list'))

@app.route('/audit_list/<get_data>')
@login_required
def auditlistdata(get_data):
    auditmethod = Auditmethod.query.filter_by(method=get_data).all()
    auditmethodArray=[]
    for auditmethod in auditmethod   :
        auditmethodobj={}
        auditmethodobj['id']=auditmethod.id
        auditmethodobj['method']=auditmethod.method
        auditmethodobj['scope']=auditmethod.scope
        auditmethodobj['doctype']=auditmethod.documentType
        auditmethodobj['description']=auditmethod.description
        auditmethodArray.append(auditmethodobj)
    return jsonify({'audits' : auditmethodArray})

# for Resource List
@app.route("/resources_list" , methods=['GET', 'POST'])
@login_required
def resources_list():
    resource=Resource.query.all()
    return render_template('resources_list.html', title='Resources List', resource=resource)

@app.route("/resources_list/create_resources", methods=['GET', 'POST'])
@login_required
def create_resources():
    form = ResourceForm()
    if form.validate_on_submit():
        resource= Resource(resourceType=form.resourceType.data,category=form.category.data, description=form.description.data, status=form.status.data,confidentiality=form.confidentiality.data, asset=form.asset.data, assetOwner=form.assetOwner.data, availability=form.availability.data, evidence=form.evidence.data, filesDescription=form.filesDescription.data, auditor=current_user)
        if form.evidence.data:
            evidence_file = save_evidence(form.evidence.data)
            current_user.evidence = evidence_file
        db.session.add(resource)
        db.session.commit()
        flash('Your asset has been created!', 'success')
        return redirect(url_for('resources_list'))
    return render_template('create_resources.html', title='Add Items (Asset Identification)', form=form)

@app.route("/resources_list/<int:resource_id>/update" , methods=['GET', 'POST'])
@login_required
def update_resources(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    form = ResourceForm()
    if form.validate_on_submit():
        resource.resourceType = form.resourceType.data
        resource.category = form.category.data
        resource.description = form.description.data
        resource.status = form.status.data
        resource.confidentiality = form.confidentiality.data
        resource.asset = form.asset.data
        resource.assetOwner = form.assetOwner.data
        resource.availability = form.availability.data
        resource.filesDescription = form.filesDescription.data
        db.session.commit()
        flash('Your asset has been updated!', 'success')
        return redirect(url_for('resources_list', resource_id=resource.id))
    elif request.method == 'GET':
        form.resourceType.data = resource.resourceType
        form.category.data = resource.category
        form.description.data = resource.description
        form.status.data = resource.status
        form.confidentiality.data = resource.confidentiality
        form.asset.data = resource.asset
        form.assetOwner.data = resource.assetOwner
        form.availability.data = resource.availability
        form.filesDescription.data = resource.filesDescription
    return render_template('create_resources.html', title='Edit Items Asset Identification', form=form)

@app.route("/resources_list/<int:resource_id>/delete" , methods=['GET','POST'])
@login_required
def delete_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    db.session.delete(resource)
    db.session.commit()
    flash('Your resource  has been deleted!', 'success')
    return redirect(url_for('resources_list'))

@app.route("/resources_share")
@login_required
def resources_share():
    return render_template('resources_share.html', title='Share Items (Asset Identification)')

# for Document List
@app.route("/document_list", methods=['GET', 'POST'])
@login_required
def document_list():
    document=Document.query.all()
    return render_template('document_list.html', title='Engagement Letter List', document=document)

@app.route("/document_list/create_document", methods=['GET', 'POST'])
@login_required
def create_document():
    form = DocumentForm()
    if form.validate_on_submit():
        document= Document(documentTitle=form.documentTitle.data,filesDescription=form.filesDescription.data, files=form.files.data, status=form.status.data, auditor=current_user)
        if form.files.data:
            files_file = save_files(form.files.data)
            current_user.files = files_file
        db.session.add(document)
        db.session.commit()
        flash('Your document has been created!', 'success')
        return redirect(url_for('document_list'))
    return render_template('create_document.html', title='Add Items (Engagement Letter)', form=form)

@app.route("/document_list/<int:document_id>/update" , methods=['GET', 'POST'])
@login_required
def update_document(document_id):
    document = Document.query.get_or_404(document_id)
    form = DocumentForm()
    if form.validate_on_submit():
        document.documentTitle = form.documentTitle.data
        document.status = form.status.data
        document.filesDescription = form.filesDescription.data
        db.session.commit()
        flash('Your asset has been updated!', 'success')
        return redirect(url_for('document_list', document_id=document.id))
    elif request.method == 'GET':
        form.documentTitle.data = document.documentTitle
        form.status.data = document.status
        form.filesDescription.data = document.filesDescription
    return render_template('create_document.html', title='Edit Items (Engagement Letter)', form=form)

@app.route("/document_list/<int:document_id>/delete" , methods=['GET','POST'])
@login_required
def delete_document(document_id):
    document = Document.query.get_or_404(document_id)
    db.session.delete(document)
    db.session.commit()
    flash('Your document has been deleted!', 'success')
    return redirect(url_for('document_list'))

# for Calendar
@app.route("/calendar")
@login_required
def calendar():
    return render_template('calendar.html')

@app.route("/index")
@login_required
def index():
    return render_template('index.html')
