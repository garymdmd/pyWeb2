from flask import Flask, render_template, request, session,redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from flask import session, url_for, redirect
import pandas as pd

# Configure the OAuth flow
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # ONLY for development!
CLIENT_SECRETS_FILE = "client_secret_247911754370-9gb3keue4tu2n7b29harrorfs7hosqjb.apps.googleusercontent.com.json"
SCOPES = ['https://www.googleapis.com/auth/calendar']

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
#app.secret_key = 'your_secret_key'  # Replace with a real secret key for production
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'xls'}

#configure sign part:
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("://", "ql://", 1) # Heroku uses 'postgres://' but SQLAlchemy expects 'postgresql://'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

# Create tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Retrieve the path of the uploaded file from the session
    uploaded_file_path = session.get('uploaded_file_path')
    
    # Check if the file path exists in the session
    if uploaded_file_path:
        try:
            # Remove the file using the os module
            os.remove(uploaded_file_path)
            flash('Uploaded file has been deleted.')
        except OSError as e:
            # The file might not exist or other error occurred during deletion
            flash('Error deleting the uploaded file - file may not exist.')
            print(e)

    # Clear all data stored in session
    session.clear()
    
    # Logout user using Flask-Login
    logout_user()
    
    flash('You have been logged out.')
    return redirect(url_for('login'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload_calendar():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'excel_file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['excel_file']
        
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(app.root_path, 'uploads')
            
            # Ensure the upload_folder exists
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            filepath = os.path.join(upload_folder, filename)
            
            # Save the file to the uploads folder
            file.save(filepath)
            
            # Now you store the filepath in the session
            session['uploaded_file_path'] = filepath
            
            # Add logic to process the file and interact with Google Calendar here
            flash('File successfully uploaded and processed')
            
            # Redirect or process the file as needed
            return redirect(url_for('upload_calendar'))
    
    # If it's not a POST request, or if no file was selected,
    # render the upload page template
    return render_template('upload.html')



@app.route('/authorize')
def authorize():
    # Create a flow instance to manage the OAuth 2.0 Authorization Grant Flow steps
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=['https://www.googleapis.com/auth/calendar'],
        redirect_uri=url_for('oauth2callback', _external=True))

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    # Store the state in the session so that the callback can verify the
    # auth server response.
    session['state'] = state

    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=['https://www.googleapis.com/auth/calendar'],
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )

    # Use the authorization server's response to fetch the OAuth 2.0 tokens
    flow.fetch_token(authorization_response=request.url)

    # # Check if the credentials are valid
    # if flow.credentials and flow.credentials.expired and flow.credentials.refresh_token:
    #     flow.credentials.refresh(Request())
    # else:
    #     # Credentials could not be refreshed, possibly handle this better in production
    #     return 'Failed to refresh credentials', 401

    # Store the credentials in the session.
    # In production, you should securely store the credentials in a database.
    session['credentials'] = {
        'token': flow.credentials.token,
        'refresh_token': flow.credentials.refresh_token,
        'token_uri': flow.credentials.token_uri,
        'client_id': flow.credentials.client_id,
        'client_secret': flow.credentials.client_secret,
        'scopes': flow.credentials.scopes
    }

    return redirect(url_for('upload_calendar'))


@app.route('/upload_gcal', methods=['POST'])
def upload_gcal():
    # Assuming the file has already been saved to a known location and filename
    filepath = session.get('uploaded_file_path')  # You'd set this during the file upload

    # Read the Excel file
    df = pd.read_excel(filepath, parse_dates=['date'])

    # Create a list to hold events
    events = []
    for index, row in df.iterrows():
        if not pd.isna(row['night']):  # Check if there's an entry for the day shift
            events.append({
                'summary': row['night'],
                'date': row['date'].strftime('%Y-%m-%d'),  # Format date for all-day event
                'calendar': 'Night'
            })
        if not pd.isna(row['day']):  # Check if there's an entry for the night shift
            events.append({
                'summary': row['day'],
                'date': row['date'].strftime('%Y-%m-%d'),  # Format date for all-day event
                'calendar': 'Day'
            })

    # Load credentials from the session
    credentials = Credentials(**session['credentials'])

    # Build the service object
    service = build('calendar', 'v3', credentials=credentials)

    # The IDs for your 'Day' and 'Night' calendars
    day_calendar_id = 'b500267a84a2e8915deac8e5b0f85bb76847fafbf1e13020a02b7d66ecb18e1a@group.calendar.google.com'
    night_calendar_id = '568afc0b9664cf0267a26033f9b7a73755bc595e5d1df318425f436eddc00080@group.calendar.google.com'

    # Now, create events in the respective calendars
    for event in events:
        event_body = {
            'summary': event['summary'],
            'start': {'date': event['date']},
            'end': {'date': event['date']},
        }
        
        calendar_id = day_calendar_id if event['calendar'] == 'Day' else night_calendar_id
        
        # Call the Calendar API to insert the event
        try:
            event_result = service.events().insert(calendarId=calendar_id, body=event_body).execute()
            print(f"Created event id: {event_result.get('id')}")
        except Exception as e:
            print(f"An error occurred: {e}")
            flash('An error occurred while uploading the events.')
            return redirect(url_for('upload_calendar'))

    flash('Events successfully uploaded to Google Calendar')
    return redirect(url_for('upload_calendar'))




# Include other routes and functions as necessary

if __name__ == '__main__':
    app.run(debug=True)
