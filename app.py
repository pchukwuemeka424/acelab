import dns.resolver
from flask import Flask, render_template, redirect, url_for, flash,request,session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from email_validator import validate_email, EmailNotValidError
import pickle
import whois
from datetime import datetime
import tldextract
import requests
import re
import socket
from urllib.parse import urlparse
import geoip2.database
import tldextract
import socket
from flask_mail import Mail, Message
from flask_login import UserMixin
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # SQLite database
db = SQLAlchemy(app)
from sqlalchemy.orm import joinedload

# Assuming you have already imported the necessary modules

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


def detect_domain_server(domain):
   try:
        # Perform DNS lookup to get IP address
        ip_address = socket.gethostbyname(domain)

        # Perform reverse DNS lookup to get server or hostname associated with IP
        server = socket.gethostbyaddr(ip_address)[0]
        
        return server
   except socket.gaierror:
        print("Error: Hostname not found.")
        return None
   except socket.herror:
        print("Error: Hostname not found.")
        return None

    
def extract_tld(url):
 # Extract the domain using tldextract
    extracted = tldextract.extract(url)
    return extracted.suffix

def domain_ip_address(url):
    try:
        result = dns.resolver.query(url, 'A')
        # Return the first IP address found
        for ipval in result:
            return ipval.to_text()
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist.")
    except dns.resolver.NoAnswer:
        print("No A record found for the domain.")
    except dns.resolver.Timeout:
        print("DNS query timed out.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    return None




def get_domain_paths(url):
    parsed_url = urlparse(url)
    return parsed_url.path

def extract_subdomains(url):

    extracted = tldextract.extract(url)
    return extracted.subdomain



    


def is_indexed_by_google(url):
    try:
        # Perform a Google search with the site: operator
        search_query = f"site:{url}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(f"https://www.google.com/search?q={search_query}", headers=headers)

        # Check if the URL appears in the search results
        if response.status_code == 200 and url in response.text:
            return True
        else:
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

    
def https_token(url):
     return url.startswith("https://")
     if has_https(url):
        print("URL contains 'https://'")
     else:
         print("URL does not contain 'https://'")

# Load the trained model from file
loaded_model = pickle.load(open('train_model.pkl', 'rb'))

# Function to preprocess the URL
def preprocess_url(url):
    # Remove http:// or https:// from the beginning of the URL
    url = url.replace('http://', '').replace('https://', '')
    return url
def shortening_service(url):

        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
        if match:
            return True               # phishing
        else:
            return False               # legitimate
        
def get_root_domain(url):
    # Extract the domain using tldextract
    ext = tldextract.extract(url)
    # Construct and return the root domain
    return f"{ext.domain}.{ext.suffix}"

# Function to calculate the age of the domain
def get_domain_age(creation_date):
    # Calculate the age of the domain
    today = datetime.now()
    age = today.year - creation_date.year - ((today.month, today.day) < (creation_date.month, creation_date.day))
    return age

# Function to get WHOIS information for a URL
def get_whois_info(url):
    try:
        whois_info = whois.whois(url)
        if whois_info:
            if isinstance(whois_info.creation_date, list):
                # In some cases, creation_date may be a list of dates (e.g., for multiple registration events)
                creation_date = min(whois_info.creation_date)
            else:
                creation_date = whois_info.creation_date
            # Get the age of the domain
            age = get_domain_age(creation_date)
            return {'domain_name': whois_info.domain_name, 'registrar': whois_info.registrar,
                    'creation_date': creation_date, 'expiration_date': whois_info.expiration_date,
                    'age': age}
    except Exception as e:
        # If an error occurs during WHOIS lookup, return None
        print(f"Error fetching WHOIS information: {str(e)}")
        return None
    

def is_ip_address(url):

    # Regular expression pattern for matching IP address
    match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
    if match:
            #print match.group()
            return True            # phishing
    else:
            #print 'No matching pattern found'
            return False            # legitimate


import requests
from bs4 import BeautifulSoup

def has_iframe(url):
    """Check if the given website contains iframes in its content.
    
    Args:
        url (str): The URL of the website.
        
    Returns:
        bool: True if iframes are found, False otherwise.
    """
    try:
        # Send a GET request to the URL
        response = requests.get(url)
        # Parse the HTML content
        soup = BeautifulSoup(response.content, 'html.parser')
        # Find all iframe elements
        iframes = soup.find_all('iframe')
        # Check if iframes are found
        return len(iframes) > 0
    except Exception as e:
        print(f"Error detecting iframes: {str(e)}")
        return False
    
def detect_obfuscated_code(url):
    """Detect potential obfuscated, base64-encoded, or encrypted JavaScript code on a website.
    
    Args:
        url (str): The URL of the website.
        
    Returns:
        bool: True if potential obfuscated code is found, False otherwise.
    """
    try:
        # Send a GET request to the URL
        response = requests.get(url)
        # Extract JavaScript code from the response
        javascript_code = response.text
        
        # Check for common patterns indicating obfuscation, base64 encoding, or encryption
        patterns = [
            r'\b(eval\s*\(.*\))\b',     # Matches eval() function calls
            r'\b(atob\s*\(.*\))\b',     # Matches atob() function calls (base64 decoding)
            r'\b(btoa\s*\(.*\))\b',     # Matches btoa() function calls (base64 encoding)
            r'\b(fromCharCode\s*\(.*\))\b',  # Matches fromCharCode() function calls (unicode encoding)
            r'\b(String\.fromCharCode\s*\(.*\))\b',  # Matches String.fromCharCode() function calls
            r'["\'](?:(?:[a-zA-Z0-9+\/]{4})*(?:[a-zA-Z0-9+\/]{2}==|[a-zA-Z0-9+\/]{3}=)?)+["\']'  # Matches base64 strings
        ]
        
        # Check for patterns indicating potential obfuscation, encoding, or encryption
        for pattern in patterns:
            if re.search(pattern, javascript_code):
                return True
        
        return False
    except Exception as e:
        print(f"Error detecting obfuscated code: {str(e)}")
        return False

def has_special_characters(url):
    # Define a regular expression pattern to match special characters
    pattern = r'[!@#$%^&*(),.?":{}|<>]'
    
    # Use re.search() to find if any special character exists in the URL
    if re.search(pattern, url):
        return True
    else:
        return False

def count_special_characters(url):
    # Define a regular expression pattern to match special characters
    pattern = r'[!@#$%^&*(),.?":{}|<>]'
    
    # Use re.findall() to find all occurrences of special characters in the URL
    special_characters = re.findall(pattern, url)
    
    # Return the count of special characters found
    return len(special_characters)

def url_length(url):
    # Use len() function to calculate the length of the URL
    return len(url)


def get_ip_reputation(api_key, url):
 
    try:
        # Construct the API URL
        api_url = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{url}"
        
        # Make a GET request to the API
        response = requests.get(api_url)
        
        # Check if request was successful (status code 200)
        if response.status_code == 200:
            # Parse the JSON response
            ip_reputation = response.json()
            return ip_reputation
        else:
            print(f"Failed to retrieve IP reputation. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    return None


import re

def list_special_characters(url):
    # Define a regular expression pattern to match special characters
    pattern = r'[!@#$%^&*(),.?":{}|<>]'
    
    # Use re.findall() to find all occurrences of special characters in the URL
    special_characters = re.findall(pattern, url)
    
    # Return the list of special characters found
    return special_characters


def check_ip_reputation(ip_address, api_key):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }

    response = requests.request(method='GET', url=url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return None

# Replace 'your_api_key' with your actual AbuseIPDB API key
api_key = 'a29955086fe0dd2a8c42331f014cfc0707ccc73eedf9e0aa2f61266d5762f186e42c0cf02b25240f'
# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'mail.acehubtechnologies.com.ng'  # Update with your SMTP server
app.config['MAIL_PORT'] = 587  # Update with your SMTP port
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'info@acehubtechnologies.com.ng'  # Update with your email address
app.config['MAIL_PASSWORD'] = 'holiday100/'  # Update with your email password

mail = Mail(app)

def check_ip_reputation(ip_address):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    headers = {
        'Key':'a29955086fe0dd2a8c42331f014cfc0707ccc73eedf9e0aa2f61266d5762f186e42c0cf02b25240f',
        'Accept': 'application/json'
    }

    response = requests.request(method='GET', url=url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return None

# Route for the index page (input form)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/assesement')
def assesement():
    return render_template('assesement.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Send email
        msg = Message(subject='Contact Form Submission',
                      sender='info@acehubtechnologies.com.ng',
                      recipients=['adampekolo31@gmail.com'])  # Update with recipient's email address
        msg.body = f"Name: {name}\nEmail: {email}\nMessage: {message}"
        mail.send(msg)

        return 'Thank you for your message! We will get back to you soon.'
    return render_template('contact.html')

# Route for predicting the URLs
@app.route('/predict', methods=['POST'])
def predict():
      
        # Get the URL from the form submission
        url = request.form['url']
        # Preprocess the URL
        query = request.form['url']
        # Get the root domain
        root_domain = get_root_domain(url)
        # Preprocess the URL
        url = preprocess_url(url)
        
        special = has_special_characters(url)
        lenght = url_length(url)
        list_special = list_special_characters(url)
        count_special = count_special_characters(url)
        paths = get_domain_paths(query)
        #shorten Url
        shorten = shortening_service(url)
        # Get WHOIS information for the URL
        whois_info = get_whois_info(root_domain)
        # Check if the URL is indexed by Google
        is_indexed = is_indexed_by_google(root_domain)
        # Check if the URL has https
        has_https = https_token(query)
         # Check if the URL is an IP address
        ip_address = is_ip_address(url)
        #extract_subdomains
        extract_sub = extract_subdomains(query)
        # Detect obfuscated code
        detect_obfuscated = detect_obfuscated_code(url)
        # Check if the URL contains iframes
        iframe = has_iframe(url)
        # Check if the URL is an IP address
        is_ip = domain_ip_address(root_domain)
        # Check if the URL is a domain name
        tld = extract_tld(root_domain)
        check_rep = check_ip_reputation(is_ip)
        Domain_server = detect_domain_server(root_domain)
        api_key = "D3aS8wtUXlNjHRu63mvIraGTeXe7NP5U"
        ip_reputation = get_ip_reputation(api_key, root_domain)
        # Make predictions
        prediction = loaded_model.predict([url])

        
        
        # Render the result template with the prediction and WHOIS information
        return render_template('result.html',check_rep=check_rep,lenght=lenght,list_special=list_special,count_special=count_special,special=special,Domain_server = Domain_server,tld=tld,ip_reputation=ip_reputation,is_ip=is_ip,detect_obfuscated=detect_obfuscated,iframe=iframe,paths=paths,extract_sub=extract_sub,query=query,has_https=has_https,ip_address=ip_address,shorten=shorten, is_indexed=is_indexed,url=url, prediction= prediction, whois_info=whois_info,root_domain=root_domain,)


# Define the SignupForm
class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Sign Up')

# Define the LoginForm
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

# Define routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user_email = User.query.filter_by(email=form.email.data).first()
        if existing_user_email:
            flash('Email already exists.', 'error')
            return redirect(url_for('signup'))

        existing_user_username = User.query.filter_by(username=form.username.data).first()
        if existing_user_username:
            flash('Username already taken.', 'error')
            return redirect(url_for('signup'))

        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Signup successful!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/check')
def check():
    return render_template('check.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, password=form.password.data).first()
        if user:
            session['username'] = user.username  # Store username in session
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Define the domainUrl model
class domainUrl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(100), nullable=False)

# Define the domainForm
class domainForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    status = StringField('Status', validators=[DataRequired()])
    submit = SubmitField('Submit')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        username = session['username']
        form = domainForm()

        if form.validate_on_submit():
            # Check if the domain already exists for the logged-in user
            existing_entry = domainUrl.query.filter_by(domain=form.domain.data, username=username).first()
            if existing_entry:
                flash('Domain already exists for the logged-in user.', 'error')
            else:
                # Create a new entry in the database
                new_entry = domainUrl(
                    domain=form.domain.data,
                    status=form.status.data,
                    timestamp=datetime.utcnow(),
                    username=username
                )
                db.session.add(new_entry)
                db.session.commit()
                flash('Data added successfully!', 'success')
            return redirect(url_for('profile'))

        # Fetch all inserted data according to the logged-in session's username
        user_entries = domainUrl.query.filter_by(username=username).all()

        # Assuming you have a User model with a method to retrieve user data
        user = User.query.filter_by(username=username).first()
        return render_template('profile.html', username=username, user=user, form=form, user_entries=user_entries)
    else:
        flash('You need to login first.', 'error')
        return redirect(url_for('login'))
    

# Define your database model
class QuizScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_session = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, nullable=False)

# Route to handle form submission
@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    try:
        user_session = session.get('username')  # Get the user session from the session data
        score = int(request.form.get('score'))

        # Create a new QuizScore object
        quiz_score = QuizScore(user_session=user_session, score=score)

        # Add the object to the database session
        db.session.add(quiz_score)

        # Commit the changes to the database
        db.session.commit()

        flash('Quiz score saved successfully', 'success')  # Flash a success message
    except Exception as e:
        db.session.rollback()
        flash('Error saving quiz score: {}'.format(str(e)), 'error')  # Flash an error message

    return redirect(url_for('assessment'))  # Redirect to the assessment page

@app.route('/assessment')
def assessment():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            print("User:", user)  # Debugging output
            return render_template('assessment.html', user=user)
        else:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
    else:
        flash('You need to login first.', 'error')
        return redirect(url_for('login'))


@app.route('/reports')
def generate_reports():
    # Fetch domain, status, and timestamp from the database
    data = domainUrl.query.with_entities(domainUrl.domain, domainUrl.status, domainUrl.timestamp).all()
    
    # Pass the fetched data to the HTML template
    return render_template('reports.html', data=data)


if __name__ == '__main__':
    with app.app_context():
        # Create the database tables
        db.create_all()
    app.run(debug=True)