
from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = "some-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///hospital.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"




class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin / doctor / patient
    is_active_user = db.Column(db.Boolean, default=True)

    doctor_profile = db.relationship("DoctorProfile", backref="user", uselist=False)
    patient_profile = db.relationship("PatientProfile", backref="user", uselist=False)

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)

    @property
    def is_active(self):
        return self.is_active_user


class Department(db.Model):
    __tablename__ = "departments"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)

    doctors = db.relationship("DoctorProfile", backref="department", lazy=True)


class DoctorProfile(db.Model):
    __tablename__ = "doctor_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    specialization = db.Column(db.String(120), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id"))
    bio = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)

    appointments = db.relationship("Appointment", backref="doctor", lazy=True)
    availability_slots = db.relationship("DoctorAvailability", backref="doctor", lazy=True)


class PatientProfile(db.Model):
    __tablename__ = "patient_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    blood_group = db.Column(db.String(5))
    address = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)

    appointments = db.relationship("Appointment", backref="patient", lazy=True)


class Appointment(db.Model):
    __tablename__ = "appointments"

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient_profiles.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("doctor_profiles.id"), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    token = db.Column(db.Integer)  #  added
    status = db.Column(db.String(20), default="Booked")  # Booked / Completed / Cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    treatment = db.relationship("Treatment", backref="appointment", uselist=False)

    __table_args__ = (
        db.UniqueConstraint("doctor_id", "date", "time", name="uix_doctor_datetime"),
    )



class Treatment(db.Model):
    __tablename__ = "treatments"

    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointments.id"), nullable=False)
    diagnosis = db.Column(db.Text)
    prescription = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DoctorAvailability(db.Model):
    __tablename__ = "doctor_availability"

    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey("doctor_profiles.id"), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("doctor_id", "date", name="uix_doctor_date"),
    )


# login

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#roles

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def get_current_doctor():
    if current_user.is_authenticated and current_user.role == "doctor":
        return DoctorProfile.query.filter_by(user_id=current_user.id).first()
    return None


def get_current_patient():
    if current_user.is_authenticated and current_user.role == "patient":
        return PatientProfile.query.filter_by(user_id=current_user.id).first()
    return None


def init_db():
    db.create_all()

    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        admin_user = User(
            username="admin",
            name="Admin User",
            email="admin@example.com",
            phone="0000000000",
            role="admin",
        )
        admin_user.set_password("admin123")
        db.session.add(admin_user)

    if Department.query.count() == 0:
        db.session.add_all([
            Department(name="Cardiology", description="Heart and blood vessel related treatments"),
            Department(name="Neurology", description="Brain and nervous system treatments"),
            Department(name="Orthopedics", description="Bone and joint treatments"),
        ])

    db.session.commit()


# routes for html 

@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        if current_user.role == "doctor":
            return redirect(url_for("doctor_dashboard"))
        if current_user.role == "patient":
            return redirect(url_for("patient_dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if not user or not user.check_password(password):
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

        if not user.is_active_user:
            flash("Your account is not active. Contact admin.", "warning")
            return redirect(url_for("login"))

        
        login_user(user)
        flash("Logged in successfully", "success")

        
        if user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif user.role == "doctor":
            doc_profile = DoctorProfile.query.filter_by(user_id=user.id).first()
            if not doc_profile.is_active:
                logout_user()
                flash("Your doctor account is not approved yet by admin.", "warning")
                return redirect(url_for("login"))
            return redirect(url_for("doctor_dashboard"))
        elif user.role == "patient":
            return redirect(url_for("patient_dashboard"))

        return redirect(url_for("index"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        email = request.form.get("email")
        phone = request.form.get("phone")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not all([name, username, email, password, confirm]):
            flash("Please fill all required fields", "warning")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing:
            flash("Username or email already exists", "danger")
            return redirect(url_for("register"))

        new_user = User(
            username=username,
            name=name,
            email=email,
            phone=phone,
            role="patient",
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()

        new_patient = PatientProfile(user_id=new_user.id)
        db.session.add(new_patient)
        db.session.commit()

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# admin routes

@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    total_doctors = DoctorProfile.query.count()
    total_patients = PatientProfile.query.count()
    total_appointments = Appointment.query.count()

    today = date.today()
    upcoming = (
        Appointment.query
        .filter(Appointment.date >= today)
        .order_by(Appointment.date, Appointment.time)
        .limit(10)
        .all()
    )

    return render_template(
        "admin/dashboard.html",
        total_doctors=total_doctors,
        total_patients=total_patients,
        total_appointments=total_appointments,
        upcoming_appointments=upcoming,
    )


@app.route("/admin/doctors")
@login_required
@role_required("admin")
def admin_doctors():
    doctors = DoctorProfile.query.all()
    departments = Department.query.all()
    return render_template(
        "admin/doctors.html",
        doctors=doctors,
        departments=departments,
    )


@app.route("/admin/doctors/add", methods=["POST"])
@login_required
@role_required("admin")
def admin_add_doctor():
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    phone = request.form.get("phone")
    specialization = request.form.get("specialization")
    department_id = request.form.get("department_id")
    password = request.form.get("password") or "doctor123"

    if not all([name, username, email, specialization]):
        flash("Please provide name, username, email and specialization", "warning")
        return redirect(url_for("admin_doctors"))

    existing = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()
    if existing:
        flash("Username or email already exists", "danger")
        return redirect(url_for("admin_doctors"))

    user = User(
        username=username,
        name=name,
        email=email,
        phone=phone,
        role="doctor",
    )
    user.set_password(password)
    db.session.add(user)
    db.session.flush()

    profile = DoctorProfile(
        user_id=user.id,
        specialization=specialization,
        department_id=department_id if department_id else None,
    )
    db.session.add(profile)
    db.session.commit()

    flash("Doctor added successfully", "success")
    return redirect(url_for("admin_doctors"))


@app.route("/admin/doctors/<int:doctor_id>/edit", methods=["POST"])
@login_required
@role_required("admin")
def admin_edit_doctor(doctor_id):
    doc = DoctorProfile.query.get_or_404(doctor_id)

    doc.user.name = request.form.get("name")
    doc.user.email = request.form.get("email")
    doc.user.phone = request.form.get("phone")
    doc.specialization = request.form.get("specialization")
    doc.department_id = request.form.get("department_id") or None
    doc.is_active = bool(request.form.get("is_active"))

    db.session.commit()
    flash("Doctor updated successfully", "success")
    return redirect(url_for("admin_doctors"))


@app.route("/admin/doctors/<int:doctor_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_delete_doctor(doctor_id):
    doc = DoctorProfile.query.get_or_404(doctor_id)
    doc.is_active = False
    doc.user.is_active_user = False
    db.session.commit()
    flash("Doctor has been deactivated/blacklisted", "info")
    return redirect(url_for("admin_doctors"))


@app.route("/admin/patients")
@login_required
@role_required("admin")
def admin_patients():
    patients = PatientProfile.query.all()
    return render_template("admin/patients.html", patients=patients)


@app.route("/admin/patients/<int:patient_id>/edit", methods=["POST"])
@login_required
@role_required("admin")
def admin_edit_patient(patient_id):
    pat = PatientProfile.query.get_or_404(patient_id)

    pat.user.name = request.form.get("name")
    pat.user.email = request.form.get("email")
    pat.user.phone = request.form.get("phone")
    pat.address = request.form.get("address")
    pat.age = request.form.get("age") or None
    pat.gender = request.form.get("gender")
    pat.blood_group = request.form.get("blood_group")
    pat.is_active = bool(request.form.get("is_active"))
    pat.user.is_active_user = pat.is_active

    db.session.commit()
    flash("Patient updated successfully", "success")
    return redirect(url_for("admin_patients"))


@app.route("/admin/patients/<int:patient_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_delete_patient(patient_id):
    pat = PatientProfile.query.get_or_404(patient_id)
    pat.is_active = False
    pat.user.is_active_user = False
    db.session.commit()
    flash("Patient has been deactivated/blacklisted", "info")
    return redirect(url_for("admin_patients"))


@app.route("/admin/appointments")
@login_required
@role_required("admin")
def admin_appointments():
    appts = Appointment.query.order_by(
        Appointment.date.desc(),
        Appointment.time.desc()
    ).all()
    return render_template("admin/appointments.html", appointments=appts)


@app.route("/admin/search")
@login_required
@role_required("admin")
def admin_search():
    q = request.args.get("q", "").strip()
    doctor_results = []
    patient_results = []

    if q:
        doctor_results = (
            DoctorProfile.query
            .join(User)
            .filter(
                (User.name.ilike(f"%{q}%")) |
                (DoctorProfile.specialization.ilike(f"%{q}%"))
            )
            .all()
        )

        patient_results = (
            PatientProfile.query
            .join(User)
            .filter(
                (User.name.ilike(f"%{q}%")) |
                (User.email.ilike(f"%{q}%")) |
                (User.phone.ilike(f"%{q}%"))
            )
            .all()
        )

    return render_template(
        "admin/search.html",
        q=q,
        doctor_results=doctor_results,
        patient_results=patient_results,
    )


#dcotore routes

@app.route("/doctor/dashboard")
@login_required
@role_required("doctor")
def doctor_dashboard():
    doc = get_current_doctor()
    if not doc:
        abort(404)

    today = date.today()
    week_later = today + timedelta(days=7)

    upcoming = (
        Appointment.query
        .filter(
            Appointment.doctor_id == doc.id,
            Appointment.date >= today,
            Appointment.date <= week_later,
        )
        .order_by(Appointment.date, Appointment.time)
        .all()
    )

    all_doc_appts = Appointment.query.filter_by(doctor_id=doc.id).all()
    patients_set = {ap.patient for ap in all_doc_appts}

    return render_template(
        "doctor/dashboard.html",
        doctor=doc,
        upcoming_appointments=upcoming,
        patients=patients_set,
    )


@app.route("/doctor/appointments/<int:appointment_id>/status", methods=["POST"])
@login_required
@role_required("doctor")
def doctor_update_appointment_status(appointment_id):
    doc = get_current_doctor()
    appt = Appointment.query.get_or_404(appointment_id)

    if appt.doctor_id != doc.id:
        abort(403)

    new_status = request.form.get("status")
    if new_status in ["Booked", "Completed", "Cancelled"]:
        appt.status = new_status
        db.session.commit()
        flash("Appointment status updated", "success")
    else:
        flash("Invalid status", "danger")

    return redirect(url_for("doctor_dashboard"))

@app.route("/admin/doctors/<int:doctor_id>/approve", methods=["POST"])
@login_required
@role_required("admin")
def admin_approve_doctor(doctor_id):
    doc = DoctorProfile.query.get_or_404(doctor_id)
    doc.is_active = True
    doc.user.is_active_user = True
    db.session.commit()
    flash("Doctor approved successfully and activated.", "success")
    return redirect(url_for("admin_doctors"))

@app.route("/register-doctor", methods=["GET", "POST"])
def register_doctor():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        email = request.form.get("email")
        phone = request.form.get("phone")
        specialization = request.form.get("specialization")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not all([name, username, email, password, confirm, specialization]):
            flash("Please fill all required fields", "warning")
            return redirect(url_for("register_doctor"))

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register_doctor"))

        user_exists = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if user_exists:
            flash("Username or email already registered", "danger")
            return redirect(url_for("register_doctor"))

        
        new_user = User(
            username=username,
            name=name,
            email=email,
            phone=phone,
            role="doctor",
            is_active_user=False        
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()

        new_doc = DoctorProfile(
            user_id=new_user.id,
            specialization=specialization,
            is_active=False             
        )
        db.session.add(new_doc)
        db.session.commit()

        flash("Doctor registration submitted. Admin approval required before login.", "info")
        return redirect(url_for("login"))

    return render_template("register_doctor.html")

@app.route("/doctor/appointments/<int:appointment_id>/treatment", methods=["GET", "POST"])
@login_required
@role_required("doctor")
def doctor_treatment(appointment_id):
    doc = get_current_doctor()
    appt = Appointment.query.get_or_404(appointment_id)

    if appt.doctor_id != doc.id:
        abort(403)

    if request.method == "POST":
        diagnosis = request.form.get("diagnosis")
        prescription = request.form.get("prescription")
        notes = request.form.get("notes")

        if appt.treatment:
            appt.treatment.diagnosis = diagnosis
            appt.treatment.prescription = prescription
            appt.treatment.notes = notes
        else:
            t = Treatment(
                appointment_id=appt.id,
                diagnosis=diagnosis,
                prescription=prescription,
                notes=notes,
            )
            db.session.add(t)

        appt.status = "Completed"
        db.session.commit()
        flash("Treatment details saved and appointment marked as Completed", "success")
        return redirect(url_for("doctor_dashboard"))

    return render_template("doctor/treatment.html", appointment=appt)


@app.route("/doctor/availability", methods=["GET", "POST"])
@login_required
@role_required("doctor")
def doctor_availability():
    doc = get_current_doctor()
    if not doc:
        abort(404)

    if request.method == "POST":
        date_str = request.form.get("date")
        start_str = request.form.get("start_time")
        end_str = request.form.get("end_time")

        try:
            avail_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            start_t = datetime.strptime(start_str, "%H:%M").time()
            end_t = datetime.strptime(end_str, "%H:%M").time()
        except Exception:
            flash("Invalid date or time format", "danger")
            return redirect(url_for("doctor_availability"))

        if start_t >= end_t:
            flash("End time must be later than start time", "warning")
            return redirect(url_for("doctor_availability"))

        
        existing = DoctorAvailability.query.filter_by(
            doctor_id=doc.id,
            date=avail_date
        ).first()

        if existing:
            existing.start_time = start_t
            existing.end_time = end_t
        else:
            new_avail = DoctorAvailability(
                doctor_id=doc.id,
                date=avail_date,
                start_time=start_t,
                end_time=end_t,
            )
            db.session.add(new_avail)

        db.session.commit()
        flash("Availability saved successfully", "success")
        return redirect(url_for("doctor_availability"))

    # fetch next 7 days' availability
    today = date.today()
    week_later = today + timedelta(days=7)

    slots = (
        DoctorAvailability.query
        .filter(
            DoctorAvailability.doctor_id == doc.id,
            DoctorAvailability.date >= today,
            DoctorAvailability.date <= week_later,
        )
        .order_by(DoctorAvailability.date)
        .all()
    )
    

    return render_template(
        "doctor/availability.html",
        doctor=doc,
        availability_list=slots,
    )


@app.route("/doctor/patients/<int:patient_id>/history")
@login_required
@role_required("doctor")
def doctor_view_patient_history(patient_id):
    doc = get_current_doctor()
    pat = PatientProfile.query.get_or_404(patient_id)

    appts = (
        Appointment.query
        .filter_by(doctor_id=doc.id, patient_id=pat.id)
        .order_by(Appointment.date.desc(), Appointment.time.desc())
        .all()
    )

    return render_template(
        "doctor/patient_history.html",
        patient=pat,
        appointments=appts,
    )


#pateint routes

@app.route("/patient/dashboard")
@login_required
@role_required("patient")
def patient_dashboard():
    pat = get_current_patient()
    if not pat:
        abort(404)

    departments = Department.query.all()

    today = date.today()
    week_later = today + timedelta(days=7)

    avail = (
        DoctorAvailability.query
        .join(DoctorProfile)
        .join(User)
        .filter(
            DoctorAvailability.date >= today,
            DoctorAvailability.date <= week_later,
            DoctorProfile.is_active == True,
            User.is_active_user == True,
        )
        .order_by(DoctorAvailability.date)
        .all()
    )

    upcoming = (
        Appointment.query
        .filter(
            Appointment.patient_id == pat.id,
            Appointment.date >= today,
        )
        .order_by(Appointment.date, Appointment.time)
        .all()
    )

    past = (
        Appointment.query
        .filter(
            Appointment.patient_id == pat.id,
            Appointment.date < today,
        )
        .order_by(Appointment.date.desc(), Appointment.time.desc())
        .all()
    )

    return render_template(
        "patient/dashboard.html",
        patient=pat,
        departments=departments,
        availability=avail,
        upcoming_appointments=upcoming,
        past_appointments=past,
    )


@app.route("/patient/profile", methods=["GET", "POST"])
@login_required
@role_required("patient")
def patient_profile():
    pat = get_current_patient()
    if not pat:
        abort(404)

    if request.method == "POST":
        pat.user.name = request.form.get("name")
        pat.user.email = request.form.get("email")
        pat.user.phone = request.form.get("phone")
        pat.address = request.form.get("address")
        pat.age = request.form.get("age") or None
        pat.gender = request.form.get("gender")
        pat.blood_group = request.form.get("blood_group")

        db.session.commit()
        flash("Profile updated", "success")
        return redirect(url_for("patient_profile"))

    return render_template("patient/profile.html", patient=pat)


@app.route("/patient/doctors")
@login_required
@role_required("patient")
def patient_doctors():
    specialization = request.args.get("specialization", "").strip()
    dep_id = request.args.get("department_id")

    query = DoctorProfile.query.join(User).filter(
        DoctorProfile.is_active == True,
        User.is_active_user == True,
    )

    if specialization:
        query = query.filter(
            DoctorProfile.specialization.ilike(f"%{specialization}%")
        )

    if dep_id:
        query = query.filter(DoctorProfile.department_id == dep_id)

    doctors = query.all()
    departments = Department.query.all()

    return render_template(
        "patient/doctors.html",
        doctors=doctors,
        departments=departments,
        specialization=specialization,
        dep_id=dep_id,
    )


@app.route("/patient/appointments/book", methods=["GET", "POST"])
@login_required
@role_required("patient")
def patient_book_appointment():
    pat = get_current_patient()
    if not pat:
        abort(404)

    
    from datetime import time
    HOSPITAL_OPEN = time(9, 0)
    HOSPITAL_CLOSE = time(17, 0)

    if request.method == "POST":
        doctor_id = request.form.get("doctor_id")
        date_str = request.form.get("date")
        time_str = request.form.get("time")

        try:
            appt_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            appt_time = datetime.strptime(time_str, "%H:%M").time()
        except:
            flash("Invalid date or time", "danger")
            return redirect(url_for("patient_book_appointment"))

        # Check hospital timing only
        if not (HOSPITAL_OPEN <= appt_time <= HOSPITAL_CLOSE):
            flash("Appointments allowed only between 09:00 AM – 05:00 PM.", "warning")
            return redirect(url_for("patient_book_appointment"))

        doc = DoctorProfile.query.get_or_404(doctor_id)
        if not doc.is_active or not doc.user.is_active_user:
            flash("Doctor is not available", "danger")
            return redirect(url_for("patient_book_appointment"))

        
        clash = Appointment.query.filter_by(
            doctor_id=doc.id,
            date=appt_date,
            time=appt_time
        ).first()
        if clash:
            flash("This time is already booked. Choose another time.", "danger")
            return redirect(url_for("patient_book_appointment"))

        
        existing = Appointment.query.filter_by(
            doctor_id=doc.id,
            date=appt_date
        ).order_by(Appointment.id.desc()).first()
        next_token = (existing.token + 1) if existing and existing.token else 1

        new_appt = Appointment(
            patient_id=pat.id,
            doctor_id=doc.id,
            date=appt_date,
            time=appt_time,
            token=next_token,
            status="Booked",
        )
        db.session.add(new_appt)
        db.session.commit()

        flash(f"Appointment booked successfully. Your token number is #{next_token}", "success")
        return redirect(url_for("patient_dashboard"))

    doctors = DoctorProfile.query.join(User).filter(
        DoctorProfile.is_active == True,
        User.is_active_user == True,
    ).all()

    return render_template("patient/book_appointment.html", doctors=doctors)

@app.route("/patient/appointments")
@login_required
@role_required("patient")
def patient_appointments():
    pat = get_current_patient()
    today = date.today()

    upcoming = (
        Appointment.query
        .filter(Appointment.patient_id == pat.id, Appointment.date >= today)
        .order_by(Appointment.date, Appointment.time)
        .all()
    )

    past = (
        Appointment.query
        .filter(Appointment.patient_id == pat.id, Appointment.date < today)
        .order_by(Appointment.date.desc(), Appointment.time.desc())
        .all()
    )

    return render_template("patient/appointments.html",
                           upcoming=upcoming,
                           past=past,
                           patient=pat)


@app.route("/doctor/queue")
@login_required
@role_required("doctor")
def doctor_queue():
    doc = get_current_doctor()
    today = date.today()

    appts = (
        Appointment.query
        .filter(Appointment.doctor_id == doc.id, Appointment.date == today)
        .order_by(Appointment.token)
        .all()
    )

    return render_template("doctor/queue.html", doctor=doc, appointments=appts)


@app.route("/patient/appointments/<int:appointment_id>/cancel", methods=["POST"])
@login_required
@role_required("patient")
def patient_cancel_appointment(appointment_id):
    pat = get_current_patient()
    appt = Appointment.query.get_or_404(appointment_id)

    if appt.patient_id != pat.id:
        abort(403)

    if appt.status == "Booked":
        appt.status = "Cancelled"
        db.session.commit()
        flash("Appointment cancelled", "info")
    else:
        flash("Only booked appointments can be cancelled", "warning")

    return redirect(url_for("patient_dashboard"))


@app.route("/patient/history")
@login_required
@role_required("patient")
def patient_history():
    pat = get_current_patient()
    if not pat:
        abort(404)

    appts = (
        Appointment.query
        .filter_by(patient_id=pat.id)
        .order_by(Appointment.date.desc(), Appointment.time.desc())
        .all()
    )

    return render_template(
        "patient/history.html",
        patient=pat,
        appointments=appts,
    )




@app.route("/api/appointments", methods=["GET"])
@login_required
def api_appointments():
    if current_user.role == "admin":
        appts = Appointment.query.all()
    elif current_user.role == "doctor":
        doc = get_current_doctor()
        appts = Appointment.query.filter_by(doctor_id=doc.id).all()
    elif current_user.role == "patient":
        pat = get_current_patient()
        appts = Appointment.query.filter_by(patient_id=pat.id).all()
    else:
        appts = []

    data = []
    for ap in appts:
        data.append({
            "id": ap.id,
            "patient": ap.patient.user.name,
            "doctor": ap.doctor.user.name,
            "date": ap.date.isoformat(),
            "time": ap.time.strftime("%H:%M"),
            "status": ap.status,
        })
    return jsonify({"appointments": data})


@app.context_processor
def inject_datetime():
    return {"datetime": datetime}


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)


