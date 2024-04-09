from flask import Flask, render_template, request
import pickle
from sklearn.ensemble import RandomForestClassifier
import sklearn
import pickle
import numpy as np
import re
import requests
from bs4 import BeautifulSoup
from googlesearch import search


app = Flask(__name__)

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

def digit_count(URL):
    digits = 0
    for i in URL:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(URL):
    letters = 0
    for i in URL:
        if i.isalpha():
            letters = letters + 1
    return letters


def sum_count_special_characters(URL):
    special_chars = ['@','?','-','=','.','#','%','+','$','!','*',',','//']

    num_special_chars = sum(char in special_chars for char in URL)
    return num_special_chars

from urllib.parse import urlparse
import re
def abnormal_url(URL):
    hostname = urlparse(URL).hostname
    hostname = str(hostname)
    match = re.search(hostname, URL)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

import re
#Use of IP or not in domain
def having_ip_address(URL):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', URL)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
    
    from urllib.parse import urlparse
import re
def abnormal_url(URL):
    hostname = urlparse(URL).hostname
    hostname = str(hostname)
    match = re.search(hostname, URL)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def httpSecured(URL):
    htp = urlparse(URL).scheme
    match = str(htp)
    if match == 'https':
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

from googlesearch import search
def google_index(URL):
    site = search(URL, 5)
    return 1 if site else 0

def Shortining_Service(URL):
    match = re.search(
                      'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      URL)
    if match:
        return 1
    else:
        return 0
    

def get_favicon_and_logo(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract favicon link
        favicon_link = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        favicon_url = favicon_link.get('href') if favicon_link else None

        # Extract logo (you may need to customize this based on the website structure)
        logo_img = soup.find('img', alt='Logo') or soup.find('img', alt='logo')
        logo_url = logo_img.get('src') if logo_img else None

        return favicon_url, logo_url
    except Exception as e:
        print(f"Error: {e}")
        return None, None


# Load the saved model
model_filename = 'rmforest_model.pkl'
with open(model_filename, 'rb') as model_file:
    loaded_model = pickle.load(model_file)

# Assuming 'get_url' is implemented somewhere in your code
def get_url(url):
    url = url.replace('www.', '')
    url_len = len(url)
    letters_count = letter_count(url)
    digits_count  = digit_count(url)
    special_chars_count = sum_count_special_characters(url)
    shortened = Shortining_Service(url)
    abnormal = abnormal_url(url)
    secure_https = httpSecured(url)
    have_ip = having_ip_address(url)
    index_google = google_index(url)
    
    parsed_url  = urlparse(url)
    
    return {
        'url_len': url_len,
        'letters_count': letters_count,
        'digits_count': digits_count,
        'special_chars_count': special_chars_count,
        'shortened': shortened,
        'abnormal': abnormal,
        'secure_http': secure_https,
        'have_ip': have_ip,
        'GoogleIndex' : index_google
    }

# Function to make predictions using the loaded model
def make_prediction(url):
    numerical_values = get_url(url)
    numerical_features = np.array(list(numerical_values.values())).reshape(1, -1)
    prediction_int = loaded_model.predict(numerical_features)[0]

    # Mapping for prediction labels
    class_mapping = {0: 'Suspicious', 1: 'Legitimate'}
    prediction_label = class_mapping.get(prediction_int, 'Unknown')
    

    return prediction_int, prediction_label

# Flask route for the index page

# Route for the index page (input)
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/predict', methods=['POST'])
def predict():
    prediction_result = None
    secure_http = None  # Initialize secure_http variable
    url_len = None
    letters_count = None
    digits_count  = None
    special_chars_count = None
    shortened = None
    abnormal = None
    have_ip = None
    index_google = None
    iframe_src = None
    favicon_url = None
    logo_url = None


    if request.method == 'POST':
        url_to_predict = request.form['url']
        prediction_int,prediction_label = make_prediction(url_to_predict)
        prediction_result = f" {prediction_label}"
        secure_http = httpSecured(url_to_predict)  # Calculate secure_http value
        url_len = len(url_to_predict)
        letters_count = letter_count(url_to_predict)
        digits_count  = digit_count(url_to_predict)
        special_chars_count = sum_count_special_characters(url_to_predict)
        shortened = Shortining_Service(url_to_predict)
        abnormal = abnormal_url(url_to_predict)
        have_ip = having_ip_address(url_to_predict)
        index_google = google_index(url_to_predict)
        url_to_preview = request.form.get('url')
        iframe_src = url_to_preview
        favicon_url, logo_url = get_favicon_and_logo(url_to_preview)
    return render_template('index.html',favicon_url=favicon_url, logo_url=logo_url,iframe_src=iframe_src,index_google=index_google,have_ip=have_ip,abnormal=abnormal,shortened=shortened,digits_count = digits_count,special_chars_count=special_chars_count, prediction_result=prediction_result,letters_count = letters_count ,secure_http=secure_http,url_len=url_len)

if __name__ == '__main__':
    app.run(debug=True)
