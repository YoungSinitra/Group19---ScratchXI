"""
forms.py — Form Validation Classes
====================================
Modular form definitions for ScratchXI (Flask-WTF pattern without the library).
Each form class: __init__ reads request.form, validate() returns (bool, errors dict).

Email domain rules:
  @dut4life.ac.za  — students ONLY (numeric student number before @)
  @dut.ac.za       — staff, security, admin ONLY
"""
import re

# ── Campus / Block Data ───────────────────────────────────────────────────────
DUT_CAMPUSES = [
    ('', 'Select campus…'),
    ('Steve Biko Campus', 'Steve Biko Campus'),
    ('ML Sultan Campus',  'ML Sultan Campus'),
    ('Ritson Campus',     'Ritson Campus'),
    ('Indumiso Campus',   'Indumiso Campus'),
    ('Riverside Campus',  'Riverside Campus'),
    ('City Campus',       'City Campus'),
]

DUT_BLOCKS = {
    # Source: DUT Steve Biko Campus official map
    'Steve Biko Campus': [
        'A1 - Botanic Mansions', 'A2 - Tromso Annex', 'A3 - Berwyn Court',
        'A4 - Berea House', 'A5 - Milena Court', 'A6 - Tromso',
        'B - S2 Block',
        'C - Alan Pittendrigh Library & Lecture Venues',
        'D1 - Lansdell', 'D2 - Exam Audit', 'D3 - Student Admissions',
        'D4 - Physical Planning / Student Housing', 'D5 - Student Housing',
        'D6 - Health Clinic',
        'E - Berea Student Residence', 'F1 - Squash Courts',
        'G1 - Security and Safety', 'G2 - Security',
        'H - Fred Crookes Sports Centre',
        'J - Student Village Residence', 'K - Stratford Student Residence',
        'L - Corlo Court Residence',
        'M - Maintenance, Facilities, Printing & Transport',
        'N - Student Residence', 'O - Open House & Open House Annex',
        'P - Scala Diner', 'Q - Student Residence', 'R - 134 Steve Biko Road',
        'S-Blocks (S2-S11) - Lecture Venues',
        'Gate 1', 'Gate 2', 'Gate 3', 'Gate 4',
        'Gate 5', 'Gate 6', 'Gate 7', 'Gate 8',
        'Parking P2', 'Parking P3', 'Parking P5', 'Parking P6',
        'Sports Field', 'Food Stalls Area',
    ],
    # Source: DUT ML Sultan Campus official map
    'ML Sultan Campus': [
        'Block A - Student Info Centre / Faculty of Management Sciences',
        'Block B - Waste Water Technology / Language & Communication',
        'Block C - ICON / Peacebuilding / Risk Office / Finance Creditors',
        'Block D - IEP International Education / Finance Budgets',
        'Block E - Statistics / Human Resources / CELT / Library & Info Studies',
        'Block F - Photography',
        'Block G - B M Patel Library',
        'Block H - Stores / Library Directorate / Gym A & B Test Venues',
        'Block J - Chemistry',
        'Block K - Sculpture & Ceramics / Emergency Medical Care & Rescue',
        'Block L - Student Bag Store',
        'Block M - Cane Growers Hall',
        'Main Entrance (ML Sultan Road)', 'Staff Entrance',
        'Gate 1', 'Gate 2',
        'North Parking', 'South Parking', 'Staff Parking',
        'Student Courtyard 1', 'Courtyard 2',
        'Curries Fountain Sports Ground',
    ],
    # Source: DUT City Campus official map
    'City Campus': [
        'Block A - Student Canteen / Interior Design / Graphic Design',
        'Block B - Graphic Design Offices',
        'Block C - Executive Deans Office / Deputy Dean / Research Office',
        'Block D - Arts Extended Programme / Journalism / Jewellery Design / Writing Centre',
        'Block E - Journalism / Fine Art (Video Technology GF)',
        'Block F - Video Technology / Journalism / Fine Art',
        'Block G - Library Study Area / Faculty Computer Lab / Graphic Design',
        'Block H - Library / Faculty Postgraduate / Computer Lab / Cashiers / Security / Clinic',
        'Block J - Faculty Boardroom (Chapel)',
        'Arthur Smith Hall',
        'Gate 1 (Anton Lembede / Smith Street - Main Entrance)',
        'Gate 2 (Dr Pixley Kaseme / West Street)',
        'Courtyard 1', 'Courtyard 2', 'Courtyard 3', 'Courtyard 4',
        'Staff Parking (North)', 'Staff Parking (South)',
    ],
    # Ritson Campus — Source: DUT official map (Winterton Walk / Ritson Road, Durban)
    'Ritson Campus': [
        # Blocks
        'Block A - Emergency Medical Care & Rescue (EMCR) Offices',
        'Block B - Information Technology',
        "Block C & E - Dean's Office (Accounting & Information)",
        'Block C & E - Auditing & Taxation',
        'Block C & E - Management Accounting',
        'Block C & E - Financial Accounting',
        'Block C & E - Office Management & Technology',
        'Block C & E - Catering Studies',
        'Block C & E - Hospitality Management',
        'Block C & E - Tourism',
        'Block D - Administration',
        'Block E & V - DUT Restaurant & Conference Centre',
        'Block G - Somatology Clinic',
        'Block G - Anatomy Laboratories',
        'Block H - Dental Technology Offices',
        'Block H - Environmental Health',
        'Block J - Health Sciences Faculty Office',
        'Block J - Somatology Office',
        'Block L - Chiropractic Clinic',
        'Block L - Homoeopathy Offices & Clinic',
        'Block M - Chiropractic Offices',
        'Block M - Human Biology Offices',
        'Block M - Radiography',
        'Block N - Television & Drama Production Studies',
        'Block N - Drama Studies',
        'Block O - Entertainment Technology (Basement, Mansfield Hall)',
        'Block P - Child & Youth Development',
        'Block Q - Horticulture',
        'Block R - EMCR Store & Training Facility',
        # Buildings & Facilities
        'Mansfield Hall - Hotel School',
        'Open House Annexe',
        'Exam Hall',
        'Canteen',
        'Business Studies Unit (BSU) - Botanic Avenue',
        # Gates
        'Gate 1 (Winterton Walk / Main Entrance)',
        'Gate 2 (Botanic Avenue)',
        'Gate 3',
        'Gate 4',
        'Gate 5 (Ritson Road)',
        'Gate 6 (Steve Biko Road)',
        'Gate 7',
        'Gate 8',
        'Gate 9',
        'Gate 10 (Lorne Street)',
        'Gatehouse',
        # Parking
        'Parking Area (Steve Biko Road)',
        'Parking Area (Open House / Annexe)',
    ],
    # Indumiso Campus — Pietermaritzburg
    # Note: Riverside/Indumiso maps were image-only scans; locations sourced from DUT records
    'Indumiso Campus': [
        # Blocks
        'Block A - Lecture Venues',
        'Block B - Lecture Venues',
        'Block C - Lecture Venues',
        'Block D - Lecture Venues',
        'Block E - Lecture Venues',
        # Buildings & Facilities
        'Administration Building',
        'Library / Learning Resource Centre',
        'Computer Lab',
        'Student Services Centre',
        'Health Clinic',
        'Student Representative Council (SRC) Office',
        'Tuck Shop / Cafeteria',
        'Chapel',
        'Sports Field',
        'Residence - Main Block',
        # Gates
        'Gate 1 (Main Entrance)',
        'Gate 2',
        # Parking
        'Student Parking',
        'Staff Parking',
    ],
    # Riverside Campus — Durban (Nursing Sciences)
    'Riverside Campus': [
        # Blocks
        'Block A - Nursing Science Lecture Venues',
        'Block B - Nursing Science Lecture Venues',
        'Block C - Midwifery / Community Health Nursing',
        'Block D - General Nursing Science',
        # Buildings & Facilities
        'Administration Block',
        'Library',
        'Computer Lab',
        'Clinical Simulation Laboratory',
        'Student Services',
        'Cafeteria / Tuck Shop',
        'Skills Laboratory',
        'Chapel',
        # Gates
        'Gate 1 (Main Entrance)',
        'Gate 2',
        # Parking
        'Student Parking',
        'Staff Parking',
    ],
}

INCIDENT_TYPES = [
    ('', 'Select type…'),
    ('Theft',                  'Theft'),
    ('Assault',                'Assault'),
    ('Emergency',              'Emergency'),
    ('Vandalism',              'Vandalism'),
    ('Fire',                   'Fire'),
    ('Medical Emergency',      'Medical Emergency'),
    ('Self Harm / Suicide',    'Self Harm / Suicide'),
    ('Other',                  'Other'),
]

SEVERITY_LEVELS = [
    ('low',      'Low'),
    ('medium',   'Medium'),
    ('high',     'High'),
    ('critical', 'Critical'),
]

PRIORITY_LEVELS = [
    ('low',      'Low'),
    ('medium',   'Medium'),
    ('high',     'High'),
    ('critical', 'Critical'),
]

ROLES = [
    ('student',  'Student'),
    ('staff',    'Staff Member'),
    ('security', 'Security Officer'),
    ('admin',    'Administrator'),
]

# PUBLIC_ROLES: shown on the registration form — admin is intentionally excluded
PUBLIC_ROLES = [
    ('student',  'Student'),
    ('staff',    'Staff Member'),
    ('security', 'Security Officer'),
]

FEEDBACK_STATUSES = [
    ('Under Investigation',          'Under Investigation'),
    ('Investigation Completed',      'Investigation Completed'),
    ('Requires Reinforcements',      'Requires Reinforcements'),
    ('Escalated',                    'Escalated'),
    ('Incident Resolved',            'Incident Resolved'),
    ('False Alarm',                  'False Alarm'),
    ('Unable to Access Location',    'Unable to Access Location'),
    ('Emergency Response Requested', 'Emergency Response Requested'),
]

ALERT_STATUSES = [
    ('open',                    'Open'),
    ('assigned',                'Assigned'),
    ('under_investigation',     'Under Investigation'),
    ('requires_reinforcements', 'Requires Reinforcements'),
    ('escalated',               'Escalated'),
    ('false_alarm',             'False Alarm'),
    ('resolved',                'Resolved'),
    ('closed',                  'Closed'),
]

TASK_STATUSES = ['assigned', 'accepted', 'in_progress', 'submitted',
                 'requires_reinforcements', 'false_alarm', 'resolved']

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# ── Domain constants ──────────────────────────────────────────────────────────
STAFF_DOMAIN   = 'dut.ac.za'        # staff, security, admin
STUDENT_DOMAIN = 'dut4life.ac.za'   # students only

# Student email: digits-only before @dut4life.ac.za  e.g. 22411296@dut4life.ac.za
STUDENT_EMAIL_RE = re.compile(r'^\d+@dut4life\.ac\.za$')

# Staff/Security/Admin: any valid local-part before @dut.ac.za
STAFF_EMAIL_RE   = re.compile(r'^[^@\s]+@dut\.ac\.za$')

# Roles that must use @dut.ac.za
STAFF_ROLES    = {'staff', 'security', 'admin'}
# Roles that must use @dut4life.ac.za
STUDENT_ROLES  = {'student'}


def allowed_image(filename):
    """Return True if filename has an allowed image extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def validate_email_for_role(email: str, role: str):
    """
    Enforce domain rules:
      student  → must be digits@dut4life.ac.za
      others   → must be *@dut.ac.za
    Returns an error string or None if valid.
    """
    email = email.lower().strip()

    if role in STUDENT_ROLES:
        if not STUDENT_EMAIL_RE.match(email):
            return (
                'Student email must use the format: studentnumber@dut4life.ac.za '
                '(numbers only before @, e.g. 22411296@dut4life.ac.za)'
            )
    elif role in STAFF_ROLES:
        if not STAFF_EMAIL_RE.match(email):
            return (
                f'Staff, Security, and Admin accounts must use a @{STAFF_DOMAIN} email address.'
            )
    return None


def validate_password_strength(password: str):
    """
    Strong password rules:
      • Minimum 8 characters
      • At least 1 uppercase letter
      • At least 1 digit
      • At least 1 special character  (!@#$%^&*()-_=+[]{}|;:',.<>?/`~)
    Returns an error string or None if valid.
    """
    if len(password) < 8:
        return 'Password must be at least 8 characters long.'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter (e.g. A–Z).'
    if not re.search(r'\d', password):
        return 'Password must contain at least one number (0–9).'
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:\',.<>?/`~]', password):
        return 'Password must contain at least one special character (e.g. !, @, #, $).'
    return None


# ── Registration Form ─────────────────────────────────────────────────────────
class RegistrationForm:
    def __init__(self, data):
        self.name     = data.get('name', '').strip()
        self.email    = data.get('email', '').strip().lower()
        self.password = data.get('password', '')
        self.role     = data.get('role', 'student')
        self.popia    = data.get('popia_consent', '')

    def validate(self):
        errors = {}

        # Name
        if not self.name or len(self.name) < 2:
            errors['name'] = 'Full name must be at least 2 characters.'

        # Email — basic format check first, then domain/role check
        if not self.email:
            errors['email'] = 'Email address is required.'
        elif '@' not in self.email:
            errors['email'] = 'Enter a valid email address.'
        else:
            domain_err = validate_email_for_role(self.email, self.role)
            if domain_err:
                errors['email'] = domain_err

        # Password — strong requirements
        if not self.password:
            errors['password'] = 'Password is required.'
        else:
            pw_err = validate_password_strength(self.password)
            if pw_err:
                errors['password'] = pw_err

        # Role — admin is never allowed through public registration
        if self.role == 'admin':
            errors['role'] = 'Admin accounts cannot be created through registration.'
        elif self.role not in [r[0] for r in PUBLIC_ROLES]:
            errors['role'] = 'Select a valid role.'

        # POPIA consent
        if not self.popia:
            errors['popia'] = 'You must accept the POPIA data consent to register.'

        return len(errors) == 0, errors


# ── Login Form ────────────────────────────────────────────────────────────────
class LoginForm:
    def __init__(self, data):
        self.email    = data.get('email', '').strip().lower()
        self.password = data.get('password', '')

    def validate(self):
        errors = {}
        if not self.email:
            errors['email'] = 'Email address is required.'
        if not self.password:
            errors['password'] = 'Password is required.'
        return len(errors) == 0, errors


# ── Alert / Incident Form ─────────────────────────────────────────────────────
class AlertForm:
    def __init__(self, data, files=None):
        self.incident_type = data.get('incident_type', '').strip()
        self.other_type    = data.get('other_type', '').strip()
        self.campus        = data.get('campus', '').strip()
        self.block         = data.get('block', '').strip()
        self.description   = data.get('description', '').strip()
        self.severity      = data.get('severity', 'medium')
        self.priority      = data.get('priority', 'medium')
        self.image         = files.get('image') if files else None

    def validate(self):
        errors = {}

        valid_types = [t[0] for t in INCIDENT_TYPES if t[0]]
        if not self.incident_type:
            errors['incident_type'] = 'Incident type is required.'
        elif self.incident_type not in valid_types:
            errors['incident_type'] = 'Select a valid incident type.'

        if self.incident_type == 'Other' and not self.other_type:
            errors['other_type'] = 'Please describe the "Other" incident type.'

        valid_campuses = [c[0] for c in DUT_CAMPUSES if c[0]]
        if not self.campus or self.campus not in valid_campuses:
            errors['campus'] = 'Select a valid campus.'

        if not self.block:
            errors['block'] = 'Block / location is required.'

        if not self.description or len(self.description) < 10:
            errors['description'] = 'Description must be at least 10 characters.'

        if self.severity not in [s[0] for s in SEVERITY_LEVELS]:
            errors['severity'] = 'Select a valid severity level.'

        if self.priority not in [p[0] for p in PRIORITY_LEVELS]:
            errors['priority'] = 'Select a valid priority level.'

        if self.image and self.image.filename and not allowed_image(self.image.filename):
            errors['image'] = 'Only image files are allowed (PNG, JPG, GIF, WEBP).'

        return len(errors) == 0, errors

    @property
    def resolved_incident_type(self):
        if self.incident_type == 'Other' and self.other_type:
            return f'Other: {self.other_type}'
        return self.incident_type


# ── Feedback / Investigation Report Form ─────────────────────────────────────
class FeedbackForm:
    def __init__(self, data, files=None):
        self.notes         = data.get('notes', '').strip()
        self.status_update = data.get('status_update', '').strip()
        self.image         = files.get('evidence') if files else None

    def validate(self):
        errors = {}

        if not self.notes or len(self.notes) < 10:
            errors['notes'] = 'Investigation notes must be at least 10 characters.'

        valid_statuses = [s[0] for s in FEEDBACK_STATUSES]
        if self.status_update not in valid_statuses:
            errors['status_update'] = 'Select a valid investigation status.'

        if self.image and self.image.filename and not allowed_image(self.image.filename):
            errors['image'] = 'Only image files are allowed (PNG, JPG, GIF, WEBP).'

        return len(errors) == 0, errors
