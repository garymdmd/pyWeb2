from flask import Flask, render_template,jsonify, request, session,redirect, url_for, flash
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
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_migrate import Migrate
from flask.cli import with_appcontext
from flask_login import login_required, current_user
import openai
from openai import OpenAI



# Configure the OAuth flow
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # ONLY for development!
CLIENT_SECRETS_FILE = "client_secret_618054310074-jrq0ou08qphacovas42255j5nctad75s.apps.googleusercontent.com.json"
SCOPES = ['https://www.googleapis.com/auth/calendar']

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
#app.secret_key = 'your_secret_key'  # Replace with a real secret key for production
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'xls'}

# Load your OpenAI API key from an environment variable
app.config['OPENAI_API_KEY'] = os.environ.get('OPENAI_API_KEY', 'default_key_for_development')
openai.api_key = app.config['OPENAI_API_KEY']

# Preloaded instructions for the assistant
assistant_instructions = """please be brief and to the point with your responses"""

#configure sign part:
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# uri = os.getenv("DATABASE_URL")  # Get the DATABASE_URL environment variable
# if uri and uri.startswith("postgres://"):
#     uri = uri.replace("postgres://", "postgresql://", 1)  # Replace "postgres://" with "postgresql://"
# uri = uri + "?sslmode=require"  # Append "?sslmode=require" to the URI

# app.config['SQLALCHEMY_DATABASE_URI'] = uri  # Set the SQLALCHEMY_DATABASE_URI configuration

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("://", "ql://", 1) # Heroku uses 'postgres://' but SQLAlchemy expects 'postgresql://'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Define Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


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
        
        # Debug print statements
        print(f"Username entered: {username}")
        print(f"Password entered: {password}")
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Debug print statement
            print(f"User found in DB: {user.username}")
            
        if user and check_password_hash(user.password_hash, password):
            
            # Debug print statement
            print("Password check passed")
            
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
    flash('User authorized.', 'success')
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

@app.route('/admin')
@login_required
def admin_page():
        print("Accessing the admin page")
        if not current_user.is_admin:
            print("Accessing the admin page")
            flash('Access denied: You must be an admin to view this page.', 'danger')
            return redirect(url_for('index'))
        else:
            print("User is admin, rendering admin page")  # Debug print
            # Your logic here...
            #return render_template('admin.html')
            users = User.query.all()  # Retrieve all users from the database
            return render_template('admin.html', users=users)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Access denied: You must be an admin to perform this action.', 'danger')
        return redirect(url_for('index'))

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    is_admin = 'is_admin' in request.form

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password_hash=hashed_password, is_admin=is_admin)
    
    db.session.add(new_user)
    db.session.commit()

    flash('User added successfully.', 'success')
    return redirect(url_for('admin_page'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied: You must be an admin to perform this action.', 'danger')
        return redirect(url_for('index'))

    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()

    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_page'))

@app.route('/chat')
def chat_page():   
    return render_template('chat.html')

# Include other routes and functions as necessary
@app.route('/ask', methods=['POST'])
def ask():
    user_input = request.json.get('question')
    
    # Combine the instructions with the user's input
    #prompt = assistant_instructions + "\n\n" + user_input
    
    # Call the OpenAI API
    client = OpenAI()
    # Assume 'prompt' contains the user's input
    # And that you maintain a list of messages as the conversation history
    #message=[{"role": "assistant", "content": gpt_assistant_prompt}, {"role": "user", "content": gpt_user_prompt}]
    # conversation_history = [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": prompt}]
    
    # response = client.chat.completions.create(
    #     model="gpt-4-1106-preview",
    #     messages=conversation_history,
    #     temperature=0.2,
    #     max_tokens=150
    # )

    # Since we're not streaming, we can just take the last response
    # The last message in the list is the assistant's response
    #assistant_message = response['choices'][0]['message']['content'].strip()
    # assistant_message = response.choices[0].message['content'].strip()
    # print(assistant_message)

    # # Return the answer as a JSON object
    # return jsonify({"response": assistant_message})

    #test prompt
    gpt_assistant_prompt = assistant_instructions
    gpt_user_prompt = user_input
    #gpt_prompt = gpt_assistant_prompt, gpt_user_prompt
    #print(gpt_prompt)
    
    
    message=[{"role": "assistant", "content": gpt_assistant_prompt}, {"role": "user", "content": gpt_user_prompt}]
    temperature=0.2
    max_tokens=256
    frequency_penalty=0.0


    response = client.chat.completions.create(
        model="gpt-4",
        messages = message,
        temperature=temperature,
        max_tokens=max_tokens,
        frequency_penalty=frequency_penalty
    )
    
    answer = response.choices[0].message
    #print(response.choices[0].message)
    print(answer)
    return jsonify({"response": answer})
   # return answer 


    # response = openai.completions.create(model="text-davinci-003",
    # prompt=prompt,
    # max_tokens=150)
    # # Extract the text from the API response and strip any leading/trailing whitespace
    # answer = response.choices[0].text.strip()
    # # Return the answer as a JSON object
    # return jsonify({"response": answer})




if __name__ == '__main__':
    app.run(debug=True)
