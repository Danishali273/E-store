import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix
import re
from dotenv import load_dotenv

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2.rfc6749.errors import InsecureTransportError, OAuth2Error
import json
import requests
import os
import oauthlib
import traceback

from models import db, Customer, Admin, Product, Category, ShoppingCart, CartItem, Order, OrderItem, ProductImage

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Add ProxyFix middleware for ngrok
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///estore.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# For development: Allow OAuth over HTTP
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development!

# Debug OAuth configuration
print(f"Google OAuth Configuration:")
print(f"GOOGLE_CLIENT_ID: {'SET - ' + GOOGLE_CLIENT_ID[:5] + '...' if GOOGLE_CLIENT_ID else 'NOT SET'}")
print(f"GOOGLE_CLIENT_SECRET: {'SET - ' + GOOGLE_CLIENT_SECRET[:5] + '...' if GOOGLE_CLIENT_SECRET else 'NOT SET'}")
print(f"OAUTHLIB_INSECURE_TRANSPORT: {os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '0')}")

# Check environment variables more thoroughly
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    print("WARNING: Google OAuth credentials are not properly set!")
    print(f"Environment variables loaded: {list(os.environ.keys())}")
    print("Make sure .env file exists and contains GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID) if GOOGLE_CLIENT_ID else None
if not client:
    print("Warning: Google OAuth client not initialized - missing GOOGLE_CLIENT_ID")

# Session Security

# --- SESSION COOKIE SETTINGS FOR MOBILE COMPATIBILITY ---
# For best mobile compatibility, especially with ngrok/tunnels:
# - SAMESITE=None (allows cross-site cookies, needed for some mobile browsers)
# - SECURE=False for local/mobile testing (set to True only if always HTTPS)

# --- DYNAMIC SESSION COOKIE SETTINGS FOR DESKTOP & MOBILE COMPATIBILITY ---
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Set defaults (will be overridden by before_request)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

# Dynamically adjust session cookie policy based on request host
@app.before_request
def set_cookie_policy():
    host = request.host.split(':')[0]
    # Localhost, 127.0.0.1, or local network IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    if (
        host in ('localhost', '127.0.0.1')
        or host.startswith('192.168.')
        or host.startswith('10.')
        or (host.startswith('172.') and 16 <= int(host.split('.')[1]) <= 31)
    ):
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['SESSION_COOKIE_SECURE'] = False
    else:
        app.config['SESSION_COOKIE_SAMESITE'] = 'None'
        app.config['SESSION_COOKIE_SECURE'] = True

# Server configuration for URL generation
app.config['PREFERRED_URL_SCHEME'] = 'https'  # Use HTTPS for ngrok

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', os.getenv('MAIL_USERNAME'))
app.config['MAIL_MAX_EMAILS'] = 10
app.config['MAIL_ASCII_ATTACHMENTS'] = False

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Helper function to check if a user is a Google user
def is_google_user(user):
    """Check if the user was authenticated via Google"""
    if not user or not hasattr(user, 'is_authenticated') or not user.is_authenticated:
        return False
        
    # Check for Google email domains
    google_domains = ['gmail.com', 'googlemail.com', 'google.com']
    user_domain = user.email.split('@')[-1].lower() if '@' in user.email else ''
    
    return user_domain in google_domains and user.email_verified

# Add helper functions to templates
@app.context_processor
def inject_user_helpers():
    return {'is_google_user': is_google_user}

# Context processor to inject current year into all templates
@app.context_processor
def inject_year():
    return {'now': datetime.now()}

# Context processor to help with URL generation for ngrok
@app.context_processor
def inject_url_scheme():
    return {'url_scheme': 'https'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_email(email):
    # Basic regex for email validation
    email_regex = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    if not re.match(email_regex, email):
        return False
    # Check for common typo: .con instead of .com
    if email.lower().endswith('.con'):
        return False
    return True

db.init_app(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    # Only load customers - admins use session-based authentication
    return Customer.query.get(int(user_id))

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Email verification functions
def generate_verification_token():
    return secrets.token_urlsafe(32)

def send_verification_email(customer):
    token = generate_verification_token()
    customer.verification_token = token
    customer.token_expiry = datetime.utcnow() + timedelta(hours=24)
    db.session.commit()
    
    # Generate verification URL with proper scheme and host for ngrok
    verification_url = url_for('verify_email', token=token, _external=True, _scheme='https')
    
    msg = Message(
        'Verify Your Email - E-Store',
        recipients=[customer.email],
        body=f'''Hello {customer.first_name},

Thank you for registering with E-Store!

Please click the following link to verify your email address:
{verification_url}

This link will expire in 24 hours.

If you didn't create an account with E-Store, please ignore this email.

Best regards,
The E-Store Team'''
    )
    
    try:
        print(f"Attempting to send email to: {customer.email}")
        print(f"Verification URL: {verification_url}")
        mail.send(msg)
        print(f"Email sent successfully to {customer.email}")
        return True
    except Exception as e:
        print(f"Error sending email to {customer.email}: {e}")
        print(f"Error type: {type(e)}")
        return False

# Enhanced Error Handling
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(413)
def file_too_large(error):
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(request.url)

# Enhanced Input Validation
def validate_phone_number(phone):
    """Validate phone number format"""
    if not phone:
        return True  # Phone is optional
    
    # Remove all non-digit characters
    digits_only = ''.join(filter(str.isdigit, phone))
    
    # Check if it's a valid length (10-15 digits)
    return 10 <= len(digits_only) <= 15

def sanitize_filename(filename):
    """Sanitize uploaded filename"""
    import re
    # Remove any path components
    filename = os.path.basename(filename)
    # Remove any non-alphanumeric characters except dots and hyphens
    filename = re.sub(r'[^a-zA-Z0-9.-]', '_', filename)
    return filename

# Routes
@app.route('/')
def home():
    products = Product.query.filter_by(is_active=True).limit(8).all()
    categories = Category.query.all()
    return render_template('index.html', products=products, categories=categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form.get('phone_number', '').strip()  # Get phone number, empty string if not provided
        
        # Email format validation
        if not is_valid_email(email):
            flash('Please enter a valid email address (e.g., user@example.com). Avoid common typos like .con', 'error')
            return redirect(url_for('register'))
        
        if Customer.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        # Phone number validation
        if phone_number and not validate_phone_number(phone_number):
            flash('Invalid phone number! Please enter a valid phone number (10-15 digits).', 'error')
            return redirect(url_for('register'))
        
        customer = Customer(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password_hash=generate_password_hash(password),
            phone_number=phone_number if phone_number else None  # Set to None if empty
        )
        db.session.add(customer)
        db.session.commit()
        
        # Send verification email
        if send_verification_email(customer):
            flash('Registration successful! Please check your email to verify your account.', 'success')
        else:
            flash('Registration successful! However, we could not send the verification email. Please check your email address or contact support.', 'warning')
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    customer = Customer.query.filter_by(verification_token=token).first()
    
    if not customer:
        flash('Invalid verification link!', 'error')
        return redirect(url_for('login'))
    
    if customer.token_expiry and customer.token_expiry < datetime.utcnow():
        flash('Verification link has expired! Please register again.', 'error')
        return redirect(url_for('register'))
    
    customer.email_verified = True
    customer.verification_token = None
    customer.token_expiry = None
    db.session.commit()
    
    flash('Email verified successfully! You can now login.', 'success')
    return redirect(url_for('login'))

@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form['email']
        customer = Customer.query.filter_by(email=email).first()
        
        if not customer:
            flash('Email not found!', 'error')
            return redirect(url_for('resend_verification'))
        
        if customer.email_verified:
            flash('Email is already verified!', 'info')
            return redirect(url_for('login'))
        
        if send_verification_email(customer):
            flash('Verification email sent successfully! Please check your email.', 'success')
        else:
            flash('Failed to send verification email. Please try again later.', 'error')
        
        return redirect(url_for('login'))
    
    return render_template('resend_verification.html')

def get_google_provider_cfg():
    try:
        print(f"Attempting to fetch Google configuration from: {GOOGLE_DISCOVERY_URL}")
        response = requests.get(GOOGLE_DISCOVERY_URL, timeout=10)
        print(f"Response status code: {response.status_code}")
        response.raise_for_status()  # Raise an exception for bad status codes
        config = response.json()
        print("Successfully fetched Google configuration")
        return config
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Google provider config: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error fetching Google provider config: {e}")
        return None

@app.route('/login/google')
def google_login():
    # Check if this request came from register page
    source_page = request.args.get('source', 'login')
    
    if not client:
        flash('Google OAuth is not configured. Please try regular login or registration.', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))

    # Get Google's provider configuration
    google_provider_cfg = get_google_provider_cfg()
    if not google_provider_cfg:
        flash('Failed to fetch Google configuration. Please try again later.', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))

    # Get the authorization endpoint
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Construct the request for Google login and scopes
    # Add source parameter to state to remember where we came from
    redirect_uri = url_for('google_callback', _external=True)
    print(f"Using redirect URI: {redirect_uri}")
    
    try:
        request_uri = client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=redirect_uri,
            scope=["openid", "email", "profile"],
            state=source_page  # Remember if this came from register or login
        )
        print(f"Redirecting to Google with URI: {request_uri}")
        return redirect(request_uri)
    except Exception as e:
        print(f"Error preparing OAuth request: {e}")
        traceback.print_exc()
        flash('Error setting up Google authentication. Please try again.', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))

@app.route('/login/google/callback')
def google_callback():
    # Get the source page from state parameter
    source_page = request.args.get('state', 'login')
    print(f"Google callback called with source_page: {source_page}")
    
    # Check if there's an error parameter
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        print(f"OAuth Error: {error} - {error_description}")
        flash(f'Google authentication error: {error_description}', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))
    
    if not client:
        print("Error: Google OAuth client not configured")
        flash('Google OAuth is not configured.', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))

    # Get the authorization code from Google
    code = request.args.get("code")
    print(f"Authorization code received: {'YES' if code else 'NO'}")
    if not code:
        error = request.args.get("error")
        error_description = request.args.get("error_description")
        print(f"Google OAuth error: {error} - {error_description}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))

    try:
        print("Starting Google OAuth token exchange...")
        
        # Get Google's provider configuration
        google_provider_cfg = get_google_provider_cfg()
        if not google_provider_cfg:
            print("Error: Failed to get Google provider configuration")
            flash('Failed to fetch Google configuration.', 'error')
            return redirect(url_for('register' if source_page == 'register' else 'login'))

        # Get tokens endpoint
        token_endpoint = google_provider_cfg["token_endpoint"]
        print(f"Token endpoint: {token_endpoint}")

        # Prepare and send the token request
        callback_uri = url_for('google_callback', _external=True)
        print(f"Callback URI for token exchange: {callback_uri}")
        print(f"Full request URL: {request.url}")
        
        try:
            token_url, headers, body = client.prepare_token_request(
                token_endpoint,
                authorization_response=request.url,
                redirect_url=callback_uri,
                code=code
            )
            
            print(f"Making token request to: {token_url}")
            print(f"Request headers: {headers}")
            print(f"Request body: {body}")
            
            token_response = requests.post(
                token_url,
                headers=headers,
                data=body,
                auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
                timeout=10  # Add timeout for better error handling
            )

            print(f"Token response status: {token_response.status_code}")
            print(f"Token response content: {token_response.text}")
        except oauthlib.oauth2.rfc6749.errors.InsecureTransportError:
            print("InsecureTransportError: OAuth2 requires HTTPS. Set OAUTHLIB_INSECURE_TRANSPORT=1 for development.")
            flash('OAuth2 requires HTTPS. For development, restart the server with OAUTHLIB_INSECURE_TRANSPORT=1', 'error')
            return redirect(url_for('register' if source_page == 'register' else 'login'))
        except Exception as e:
            print(f"Exception during token request: {e}")
            print(f"Exception type: {type(e)}")
            traceback.print_exc()
            flash('Error during Google authentication. Please try again.', 'error')
            return redirect(url_for('register' if source_page == 'register' else 'login'))

        # Check if token request was successful
        if token_response.status_code != 200:
            print(f"Token request failed with status {token_response.status_code}")
            flash('Failed to authenticate with Google. Please try again.', 'error')
            return redirect(url_for('register' if source_page == 'register' else 'login'))

        # Parse the token response
        token_json = token_response.json()
        print(f"Token JSON: {token_json}")
        client.parse_request_body_response(json.dumps(token_json))

        # Get user info from Google
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        print(f"Userinfo endpoint: {userinfo_endpoint}")
        
        try:
            uri, headers, body = client.add_token(userinfo_endpoint)
            print(f"Userinfo request URI: {uri}")
            print(f"Userinfo request headers: {headers}")
            
            userinfo_response = requests.get(uri, headers=headers, data=body, timeout=10)
            
            print(f"Userinfo response status: {userinfo_response.status_code}")
            print(f"Userinfo response content: {userinfo_response.text}")
            
            # Check if userinfo request was successful
            if userinfo_response.status_code != 200:
                print(f"Userinfo request failed with status {userinfo_response.status_code}")
                flash('Failed to get user information from Google. Please try again.', 'error')
                return redirect(url_for('register' if source_page == 'register' else 'login'))
            
            user_info = userinfo_response.json()
            print(f"User info: {user_info}")
            
            # Check if email is present and verified
            if not user_info.get("email"):
                print("No email found in Google account info")
                flash('Your Google account does not have an email address. Please use a different Google account.', 'error')
                return redirect(url_for('register' if source_page == 'register' else 'login'))
                
            if not user_info.get("email_verified"):
                print("Google account email is not verified")
                flash('Your Google account email is not verified. Please verify your email with Google first.', 'error')
                return redirect(url_for('register' if source_page == 'register' else 'login'))
                
            google_email = user_info["email"]
            google_name = user_info["name"]
            first_name = user_info.get("given_name", "")
            last_name = user_info.get("family_name", "")

            print(f"Processing user: {google_email}")

            # Check if user exists
            customer = Customer.query.filter_by(email=google_email).first()
            if not customer:
                print(f"Creating new customer with Google email: {google_email}")
                # Create new customer with Google account
                customer = Customer(
                    email=google_email,
                    first_name=first_name,
                    last_name=last_name,
                    password_hash=generate_password_hash(secrets.token_urlsafe(32)),
                    email_verified=True  # Auto-verify Google users
                )
                db.session.add(customer)
                db.session.commit()
                print("New customer created successfully")
                flash('Welcome! Your Google account has been successfully registered and verified.', 'success')
            elif not customer.email_verified:
                print(f"Verifying existing customer with email: {google_email}")
                # If existing unverified user, verify them
                customer.email_verified = True
                db.session.commit()
                print("Customer verified successfully")
                flash('Welcome back! Your email has been verified with Google.', 'success')
            else:
                print(f"Existing verified customer logging in: {google_email}")
                # Existing verified user logging in
                flash('Welcome back! You have successfully signed in with Google.', 'success')

            print(f"Logging in customer: {customer.email}, ID: {customer.customer_id}")
            login_user(customer)
            print("Customer logged in successfully, redirecting to home")
            return redirect(url_for('home'))
            
        except Exception as e:
            print(f"Error processing user info: {e}")
            traceback.print_exc()
            flash(f'Error processing Google account: {str(e)}', 'error')
            return redirect(url_for('register' if source_page == 'register' else 'login'))

    except requests.exceptions.RequestException as e:
        print(f"Network error in Google callback: {e}")
        flash('Network error while connecting to Google. Please check your internet connection and try again.', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))
    except oauthlib.oauth2.rfc6749.errors.InsecureTransportError:
        print("InsecureTransportError: OAuth2 requires HTTPS. Set OAUTHLIB_INSECURE_TRANSPORT=1 for development.")
        flash('OAuth2 requires HTTPS for security. A development environment exception has been set.', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))
    except Exception as e:
        print(f"Unexpected error in Google callback: {e}")
        print(f"Error type: {type(e)}")
        traceback.print_exc()
        flash(f'Failed to log in with Google. Please try again. Error: {str(e)}', 'error')
        return redirect(url_for('register' if source_page == 'register' else 'login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        
        customer = Customer.query.filter_by(email=email).first()
        if customer and check_password_hash(customer.password_hash, password):
            if not customer.email_verified:
                flash('Please verify your email address before logging in. Check your email for the verification link.', 'warning')
                return redirect(url_for('login'))
            
            login_user(customer)
            # Add debugging
            print(f"Customer logged in: {customer.email}, ID: {customer.customer_id}, Type: {type(customer)}")
            return redirect(url_for('home'))
        else:
            if not customer:
                flash('Customer not found!', 'error')
            elif not check_password_hash(customer.password_hash, password):
                flash('Invalid password!', 'error')
            else:
                flash('Invalid email or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/logout/confirm')
@login_required
def logout_confirm():
    return render_template('logout_confirm.html')

@app.route('/products')
def products():
    # Get query parameters
    category_id = request.args.get('category', type=int)
    search = request.args.get('search', '').strip()
    sort_by = request.args.get('sort', '')
    
    # Start with base query for active products
    query = Product.query.filter_by(is_active=True)
    
    # Apply category filter
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    # Apply search filter
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Product.name.ilike(search_term),
                Product.description.ilike(search_term),
                Product.sku.ilike(search_term)
            )
        )
    
    # Apply sorting
    if sort_by == 'name':
        query = query.order_by(Product.name.asc())
    elif sort_by == 'name_desc':
        query = query.order_by(Product.name.desc())
    elif sort_by == 'price_low':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price_high':
        query = query.order_by(Product.price.desc())
    else:
        # Default sorting by creation date (newest first)
        query = query.order_by(Product.created_at.desc())
    
    # Execute query
    products = query.all()
    categories = Category.query.all()
    
    return render_template('products.html', 
                         products=products, 
                         categories=categories,
                         selected_category=category_id,
                         search_term=search,
                         sort_by=sort_by)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/cart')
@login_required
def cart():
    # Get or create a cart for the current user
    cart = current_user.shopping_carts.first()
    if not cart:
        cart = ShoppingCart(customer_id=current_user.customer_id)
        db.session.add(cart)
        db.session.commit()

    # Use the relationship to get cart items
    cart_items = cart.items
    total = 0
    items_with_products = []
    
    for item in cart_items:
        # Use the item.product relationship, which is more efficient
        if item.product:
            item_total = float(item.product.price) * item.quantity
            total += item_total
            items_with_products.append({
                'item': item,
                'product': item.product,
                'total': item_total
            })
    
    return render_template('cart.html', cart_items=items_with_products, total=total)

@app.route('/checkout')
@login_required
def checkout():
    cart = current_user.shopping_carts.first()
    if not cart or not cart.items:
        flash('Your cart is empty!', 'error')
        return redirect(url_for('cart'))
    
    cart_items = cart.items
    total = 0
    items_with_products = []
    
    for item in cart_items:
        if item.product:
            item_total = float(item.product.price) * item.quantity
            total += item_total
            items_with_products.append({
                'item': item,
                'product': item.product,
                'total': item_total
            })
    
    # Redirect to COD checkout page
    return render_template('cod_checkout.html', cart_items=items_with_products, total=total)

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    try:
        product_id = request.form.get('product_id', type=int)
        quantity = request.form.get('quantity', type=int, default=1)
        
        if not product_id:
            return jsonify({'success': False, 'message': 'Product ID is required'}), 400
        
        product = Product.query.get(product_id)
        if not product or not product.is_active:
            return jsonify({'success': False, 'message': 'Product not found or unavailable'}), 404
        
        if product.stock_quantity < quantity:
            return jsonify({'success': False, 'message': f'Only {product.stock_quantity} items available in stock'}), 400
        
        cart = current_user.shopping_carts.first()
        if not cart:
            cart = ShoppingCart(customer_id=current_user.customer_id)
            db.session.add(cart)
            db.session.commit()
        
        existing_item = cart.items.filter_by(product_id=product_id).first()
        
        if existing_item:
            new_quantity = existing_item.quantity + quantity
            if new_quantity > product.stock_quantity:
                return jsonify({'success': False, 'message': f'Cannot add more. Only {product.stock_quantity} available in stock'}), 400
            existing_item.quantity = new_quantity
        else:
            new_item = CartItem(cart_id=cart.cart_id, product_id=product_id, quantity=quantity)
            db.session.add(new_item)
        
        db.session.commit()
        
        # Get updated cart count
        cart_count = cart.items.count()
        
        return jsonify({
            'success': True, 
            'message': f'{product.name} added to cart!',
            'cart_count': cart_count
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error adding to cart: {e}")
        return jsonify({'success': False, 'message': 'Error adding product to cart.'}), 500

@app.route('/update_cart', methods=['POST'])
@login_required
def update_cart():
    try:
        cart_item_id = request.form.get('cart_item_id', type=int)
        quantity = request.form.get('quantity', type=int)

        if cart_item_id is None or quantity is None:
            return jsonify({'success': False, 'message': 'Invalid request parameters.'}), 400

        cart_item = CartItem.query.get(cart_item_id)
        # Security check: ensure the item belongs to the current user's cart
        if not cart_item or cart_item.cart.customer_id != current_user.customer_id:
            return jsonify({'success': False, 'message': 'Cart item not found.'}), 404

        product = cart_item.product
        
        # Item removal logic
        if quantity <= 0:
            db.session.delete(cart_item)
            message = f'"{product.name}" removed from cart.'
            item_removed = True
        else:
            # Item update logic
            if quantity > product.stock_quantity:
                return jsonify({
                    'success': False, 
                    'message': f'Only {product.stock_quantity} available for "{product.name}".',
                    'max_quantity': product.stock_quantity
                }), 400
            
            cart_item.quantity = quantity
            message = 'Cart updated successfully.'
            item_removed = False
        
        db.session.commit()

        # Recalculate cart totals for the response
        cart = current_user.shopping_carts.first()
        subtotal = sum(float(item.product.price) * item.quantity for item in cart.items)
        item_total = float(product.price) * quantity if not item_removed else 0

        return jsonify({
            'success': True,
            'message': message,
            'item_removed': item_removed,
            'item_total': f'{item_total:.2f}',
            'cart_subtotal': f'{subtotal:.2f}',
            'cart_tax': f'{subtotal * 0.08:.2f}',
            'cart_total': f'{subtotal * 1.08:.2f}',
            'cart_count': cart.items.count()
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error updating cart: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred.'}), 500

@app.route('/cart_count')
@login_required
def cart_count():
    cart = current_user.shopping_carts.first()
    count = cart.items.count() if cart else 0
    return jsonify({'count': count})

@app.route('/api/cart')
@login_required
def api_cart():
    """API endpoint to get cart data for the sliding cart"""
    cart = current_user.shopping_carts.first()
    if not cart:
        return jsonify({'success': False, 'message': 'Cart not found'})

    cart_items = cart.items
    total = 0
    items_data = []
    
    for item in cart_items:
        if item.product:
            item_total = float(item.product.price) * item.quantity
            total += item_total
            items_data.append({
                'cart_item_id': item.cart_item_id,
                'quantity': item.quantity,
                'total': item_total,
                'product': {
                    'product_id': item.product.product_id,
                    'name': item.product.name,
                    'price': float(item.product.price),
                    'image_url': item.product.image_url,
                    'stock_quantity': item.product.stock_quantity
                }
            })
    
    return jsonify({
        'success': True,
        'cart_items': items_data,
        'total': total,
        'cart_count': len(items_data)
    })
    

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password) and admin.is_active:
            # Use session instead of Flask-Login for admin
            session['admin_id'] = admin.admin_id
            session['admin_username'] = admin.username
            session['admin_name'] = f"{admin.first_name} {admin.last_name}"
            # Add some debugging
            print(f"Admin logged in: {admin.username}, ID: {admin.admin_id}")
            return redirect(url_for('admin_dashboard'))
        else:
            if not admin:
                flash('Admin user not found!', 'error')
            elif not check_password_hash(admin.password_hash, password):
                flash('Invalid password!', 'error')
            elif not admin.is_active:
                flash('Admin account is disabled!', 'error')
            else:
                flash('Invalid username or password!', 'error')
    
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    session.pop('admin_name', None)
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    total_products = Product.query.count()
    # Only count verified customers for accurate metrics
    total_customers = Customer.query.filter_by(email_verified=True).count()
    total_categories = Category.query.count()
    total_orders = Order.query.count()
    
    # Calculate total revenue
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    
    # Calculate average order value
    avg_order_value = db.session.query(db.func.avg(Order.total_amount)).scalar() or 0
    
    # Calculate revenue by status
    delivered_revenue = db.session.query(db.func.sum(Order.total_amount)).filter(Order.status == 'delivered').scalar() or 0
    pending_revenue = db.session.query(db.func.sum(Order.total_amount)).filter(Order.status == 'pending').scalar() or 0
    
    # Calculate order counts by status
    pending_orders = Order.query.filter_by(status='pending').count()
    processing_orders = Order.query.filter_by(status='processing').count()
    shipped_orders = Order.query.filter_by(status='shipped').count()
    delivered_orders = Order.query.filter_by(status='delivered').count()
    
    recent_products = Product.query.order_by(Product.created_at.desc()).limit(5).all()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                         total_products=total_products,
                         total_customers=total_customers,
                         total_categories=total_categories,
                         total_orders=total_orders,
                         total_revenue=total_revenue,
                         avg_order_value=avg_order_value,
                         delivered_revenue=delivered_revenue,
                         pending_revenue=pending_revenue,
                         pending_orders=pending_orders,
                         processing_orders=processing_orders,
                         shipped_orders=shipped_orders,
                         delivered_orders=delivered_orders,
                         recent_products=recent_products,
                         recent_orders=recent_orders)

@app.route('/admin/products')
@admin_required
def admin_products():
    # Get filter params
    search = request.args.get('search', '').strip()
    sku = request.args.get('sku', '').strip()
    category_id = request.args.get('category', type=int)
    status = request.args.get('status', '')
    price_min = request.args.get('price_min', type=float)
    price_max = request.args.get('price_max', type=float)

    query = Product.query
    if search:
        query = query.filter(Product.name.ilike(f'%{search}%'))
    if sku:
        query = query.filter(Product.sku.ilike(f'%{sku}%'))
    if category_id:
        query = query.filter(Product.category_id == category_id)
    if status == 'active':
        query = query.filter(Product.is_active == True)
    elif status == 'inactive':
        query = query.filter(Product.is_active == False)
    if price_min is not None:
        query = query.filter(Product.price >= price_min)
    if price_max is not None:
        query = query.filter(Product.price <= price_max)

    products = query.order_by(Product.created_at.desc()).all()
    categories = Category.query.all()
    return render_template('admin/products.html', products=products, categories=categories, search=search, sku=sku, category_id=category_id, status=status, price_min=price_min, price_max=price_max)

@app.route('/admin/products/add', methods=['GET', 'POST'])
@admin_required
def admin_add_product():
    from models import Category
    categories = Category.query.all()
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        sku = request.form['sku']
        stock_quantity = request.form['stock_quantity']
        is_active = 'is_active' in request.form
        category_id = request.form.get('category_id', type=int)
        main_image_index = int(request.form.get('main_image_index', 0))

        # Validate SKU uniqueness
        if Product.query.filter_by(sku=sku).first():
            flash('SKU already exists!', 'error')
            return render_template('admin/add_product.html', categories=categories)

        # Create product (no image_url, handled by ProductImage)
        product = Product(
            name=name,
            description=description,
            price=price,
            sku=sku,
            stock_quantity=int(stock_quantity),
            image_url=None,
            is_active=is_active
        )
        product.category_id = category_id
        db.session.add(product)
        db.session.flush()  # Get product_id

        # Handle multiple image uploads
        files = request.files.getlist('image_upload')
        if not files or not files[0].filename:
            flash('Please upload at least one product image!', 'error')
            return render_template('admin/add_product.html', categories=categories)

        for idx, file in enumerate(files):
            if file and file.filename and allowed_file(file.filename):
                safe_filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{idx}_{safe_filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_url = url_for('static', filename=f'uploads/{filename}')
                is_main = (idx == main_image_index)
                # Set product.image_url to main image for legacy compatibility
                if is_main:
                    product.image_url = image_url
                product_image = ProductImage(
                    product_id=product.product_id,
                    image_url=image_url,
                    is_main=is_main
                )
                db.session.add(product_image)
            else:
                flash('Invalid image file! Please select valid images (PNG, JPG, JPEG, GIF, WEBP)', 'error')
                return render_template('admin/add_product.html', categories=categories)

        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_products'))
    return render_template('admin/add_product.html', categories=categories)

@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_product(product_id):
    from models import Category, ProductImage
    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()
    
    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = request.form['price']
        product.sku = request.form['sku']
        product.stock_quantity = int(request.form['stock_quantity'])
        is_active = 'is_active' in request.form
        category_id = request.form.get('category_id', type=int)
        product.is_active = is_active
        product.category_id = category_id

        # Handle deleted images
        deleted_images = request.form.get('deleted_images', '')
        if deleted_images:
            ids_to_delete = [int(i) for i in deleted_images.split(',') if i.strip().isdigit()]
            for img_id in ids_to_delete:
                img = ProductImage.query.get(img_id)
                if img and img.product_id == product.product_id:
                    db.session.delete(img)

        # Handle new image uploads
        files = request.files.getlist('image_upload')
        for file in files:
            if file and file.filename and allowed_file(file.filename):
                safe_filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{safe_filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_url = url_for('static', filename=f'uploads/{filename}')
                is_main = False
                product_image = ProductImage(
                    product_id=product.product_id,
                    image_url=image_url,
                    is_main=is_main
                )
                db.session.add(product_image)

        db.session.flush()  # Ensure product.images is up to date

        # Handle main image selection robustly
        main_image_id = request.form.get('main_image_id', type=str)
        main_image_url = None
        found_main = False
        for img in product.images:
            # main_image_id can be int (existing) or 'new_x' (new uploads, but new uploads get is_main=False above)
            if str(img.image_id) == str(main_image_id):
                img.is_main = True
                main_image_url = img.image_url
                found_main = True
            else:
                img.is_main = False

        # If no main image selected or all images deleted, pick first available as main
        if not found_main:
            for img in product.images:
                img.is_main = True
                main_image_url = img.image_url
                break

        # If there is a main image, set product.image_url for legacy compatibility
        if main_image_url:
            product.image_url = main_image_url
        else:
            product.image_url = None

        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('admin_products'))
    
    return render_template('admin/edit_product.html', product=product, categories=categories)

@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/categories')
@admin_required
def admin_categories():
    categories = Category.query.all()
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/categories/add', methods=['GET', 'POST'])
@admin_required
def admin_add_category():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        category = Category(name=name, description=description)
        db.session.add(category)
        db.session.commit()
        
        flash('Category added successfully!', 'success')
        return redirect(url_for('admin_categories'))
    
    return render_template('admin/add_category.html')

@app.route('/admin/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    if request.method == 'POST':
        category.name = request.form['name']
        category.description = request.form['description']
        
        db.session.commit()
        flash('Category updated successfully!', 'success')
        return redirect(url_for('admin_categories'))
    
    return render_template('admin/edit_category.html', category=category)

@app.route('/admin/categories/delete/<int:category_id>', methods=['POST'])
@admin_required
def admin_delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('admin_categories'))

@app.route('/admin/customers')
@admin_required
def admin_customers():
    # Only show customers who have verified their email
    customers = Customer.query.filter_by(email_verified=True).all()
    return render_template('admin/customers.html', customers=customers)

@app.route('/admin/customers/unverified')
@admin_required
def admin_unverified_customers():
    # Show customers who haven't verified their email (for admin reference)
    customers = Customer.query.filter_by(email_verified=False).all()
    return render_template('admin/unverified_customers.html', customers=customers)

@app.route('/admin/orders')
@admin_required
def admin_orders():
    # Get filter params
    order_number = request.args.get('order_number', '').strip()
    recipient = request.args.get('recipient', '').strip()
    status = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    total_min = request.args.get('total_min', type=float)
    total_max = request.args.get('total_max', type=float)

    query = Order.query
    if order_number:
        query = query.filter(Order.order_number.ilike(f'%{order_number}%'))
    if recipient:
        query = query.filter(Order.recipient_name.ilike(f'%{recipient}%'))
    if status:
        query = query.filter(Order.status == status)
    if date_from:
        try:
            from datetime import datetime
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Order.created_at >= date_from_obj)
        except Exception:
            pass
    if date_to:
        try:
            from datetime import datetime, timedelta
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            date_to_obj = date_to_obj.replace(hour=23, minute=59, second=59)
            query = query.filter(Order.created_at <= date_to_obj)
        except Exception:
            pass
    if total_min is not None:
        query = query.filter(Order.total_amount >= total_min)
    if total_max is not None:
        query = query.filter(Order.total_amount <= total_max)

    orders = query.order_by(Order.created_at.desc()).all()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).scalar() or 0
    return render_template('admin/orders.html', orders=orders, total_revenue=total_revenue, order_number=order_number, recipient=recipient, status=status, date_from=date_from, date_to=date_to, total_min=total_min, total_max=total_max)

@app.route('/admin/orders/<int:order_id>')
@admin_required
def admin_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    order_items = OrderItem.query.filter_by(order_id=order_id).all()
    customer = Customer.query.get(order.customer_id)
    return render_template('admin/order_detail.html', order=order, order_items=order_items, customer=customer)

@app.route('/admin/orders/<int:order_id>/update_status', methods=['POST'])
@admin_required
def admin_update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    if new_status in ['pending', 'processing', 'shipped', 'delivered', 'cancelled']:
        order.status = new_status
        db.session.commit()
        flash(f'Order status updated to {new_status.title()}', 'success')
    else:
        flash('Invalid status', 'error')
    return redirect(url_for('admin_order_detail', order_id=order_id))

@app.route('/profile')
@login_required
def profile():
    # Get user's orders from the Order model
    orders = Order.query.filter_by(customer_id=current_user.customer_id).order_by(Order.created_at.desc()).all()
    return render_template('profile.html', orders=orders)

@app.route('/orders')
@login_required
def orders():
    # Get user's orders from the Order model
    orders = Order.query.filter_by(customer_id=current_user.customer_id).order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=orders)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.first_name = request.form['first_name']
        current_user.last_name = request.form['last_name']
        current_user.phone_number = request.form['phone_number']
        
        # Check if email is being changed
        new_email = request.form['email']
        if new_email != current_user.email:
            if Customer.query.filter_by(email=new_email).first():
                flash('Email already registered!', 'error')
                return redirect(url_for('edit_profile'))
            current_user.email = new_email
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html')

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    # Check if this is a Google-authenticated user setting a password for the first time
    is_setting_password = 'set_password' in request.form
    google_user = is_google_user(current_user)
    
    # Only check current password if not setting a new password for Google auth account
    if not is_setting_password and not google_user and not check_password_hash(current_user.password_hash, current_password):
        flash('Current password is incorrect!', 'error')
        return redirect(url_for('edit_profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match!', 'error')
        return redirect(url_for('edit_profile'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters long!', 'error')
        return redirect(url_for('edit_profile'))
    
    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    if is_setting_password or google_user:
        flash('Password set successfully! You can now login with your email and password.', 'success')
    else:
        flash('Password changed successfully!', 'success')
        
    return redirect(url_for('edit_profile'))

@app.route('/upload_image', methods=['POST'])
@admin_required
def upload_image():
    if 'image' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'})
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    if file and file.filename and allowed_file(file.filename):
        # Ensure filename is not None before passing to secure_filename
        safe_filename = secure_filename(file.filename) if file.filename else 'image'
        # Add timestamp to make filename unique
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{safe_filename}"
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        image_url = url_for('static', filename=f'uploads/{filename}')
        return jsonify({'success': True, 'image_url': image_url})
    else:
        return jsonify({'success': False, 'message': 'Invalid file type. Please select a valid image file.'})

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/process_cod_order', methods=['POST'])
@login_required
def process_cod_order():
    try:
        cart = current_user.shopping_carts.first()
        if not cart or not cart.items:
            return jsonify({'success': False, 'message': 'Cart is empty'})
        
        # Get COD form data
        recipient_name = request.form.get('recipient_name', '').strip()
        recipient_phone = request.form.get('recipient_phone', '').strip()
        recipient_email = request.form.get('recipient_email', '').strip()
        shipping_address = request.form.get('shipping_address', '').strip()
        city = request.form.get('city', '').strip()
        state = request.form.get('state', '').strip()
        postal_code = request.form.get('postal_code', '').strip()
        country = request.form.get('country', 'Pakistan').strip()
        delivery_notes = request.form.get('delivery_notes', '').strip()
        
        # Validate required fields
        if not all([recipient_name, recipient_phone, shipping_address, city, state, postal_code]):
            return jsonify({'success': False, 'message': 'Please fill in all required fields'})
        
        # Validate phone number
        if not validate_phone_number(recipient_phone):
            return jsonify({'success': False, 'message': 'Invalid phone number format'})
        
        cart_items = cart.items
        
        # Calculate total and validate stock
        total_amount = 0
        order_items_data = []
        
        for cart_item in cart_items:
            product = cart_item.product
            if not product or not product.is_active:
                return jsonify({'success': False, 'message': f'Product "{product.name if product else "Unknown"}" is no longer available'})
            
            # Check stock availability
            if product.stock_quantity < cart_item.quantity:
                return jsonify({'success': False, 'message': f'Insufficient stock for "{product.name}". Only {product.stock_quantity} available'})
            
            item_total = float(product.price) * cart_item.quantity
            total_amount += item_total
            
            order_items_data.append({
                'product': product,
                'quantity': cart_item.quantity,
                'price': product.price,
                'total': item_total
            })

        # Add tax (8%)
        total_amount = total_amount * 1.08

        # Generate order number
        order_number = f"COD-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
        
        # Create COD order
        order = Order(
            customer_id=current_user.customer_id,
            order_number=order_number,
            total_amount=total_amount,
            recipient_name=recipient_name,
            recipient_phone=recipient_phone,
            recipient_email=recipient_email if recipient_email else None,
            shipping_address=shipping_address,
            city=city,
            state=state,
            postal_code=postal_code,
            country=country,
            delivery_notes=delivery_notes if delivery_notes else None,
            status='pending'
        )
        db.session.add(order)
        db.session.flush()  # Get the order ID

        # Create order items and update stock
        for item_data in order_items_data:
            order_item = OrderItem(
                order_id=order.order_id,
                product_id=item_data['product'].product_id,
                quantity=item_data['quantity'],
                price=item_data['price']
            )
            db.session.add(order_item)

            # Update product stock
            item_data['product'].stock_quantity -= item_data['quantity']
        
        # Clear cart
        db.session.delete(cart)
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Order placed successfully!',
            'order_id': order.order_id,
            'order_number': order.order_number
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error processing COD order: {e}")
        return jsonify({'success': False, 'message': 'Error processing order. Please try again.'})

@app.route('/process_order', methods=['POST'])
@login_required
def process_order():
    # Redirect to COD process since we only support COD now
    return redirect(url_for('checkout'))

@app.route('/remove_from_cart', methods=['POST'])
@login_required
def remove_from_cart():
    """Remove item from cart"""
    try:
        cart_item_id = request.form.get('cart_item_id', type=int)

        if cart_item_id is None:
            return jsonify({'success': False, 'message': 'Invalid request parameters.'}), 400

        cart_item = CartItem.query.get(cart_item_id)
        # Security check: ensure the item belongs to the current user's cart
        if not cart_item or cart_item.cart.customer_id != current_user.customer_id:
            return jsonify({'success': False, 'message': 'Cart item not found.'}), 404

        product_name = cart_item.product.name
        db.session.delete(cart_item)
        db.session.commit()

        # Recalculate cart count
        cart = current_user.shopping_carts.first()
        cart_count = cart.items.count() if cart else 0

        return jsonify({
            'success': True,
            'message': f'"{product_name}" removed from cart.',
            'cart_count': cart_count
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error removing from cart: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred.'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Run with host 0.0.0.0 to allow external connections (needed for ngrok)
    app.run(host='0.0.0.0', port=5000, debug=True)