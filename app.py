import time
time.sleep(1)
import os
import json
from flask import Flask, redirect, request, session, url_for, session, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
from flask_sqlalchemy import SQLAlchemy
from flask import Flask


app = Flask(__name__)
app.secret_key = "123456"

# ----------config---------- 
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # ONLY for local dev (http). Remove in production.
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile",]
REDIRECT_URI = "http://127.0.0.1:5000/callback"



# ---------- DATABASE SETUP ----------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# ---------- USER MODEL ----------
class User(db.Model):
    id = db.Column(db.String(100), primary_key=True)  # Google user ID
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    picture = db.Column(db.String(200))

# Create the database tables
with app.app_context():
  db.create_all()



# ---------- ROUTES ----------
@app.route("/")
def index():
    user = session.get("user")
    return render_template(
        "home.html",
        user=user
        )

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",  # to get refresh token (only first consent)
        include_granted_scopes="true",
        prompt="consent"  # force consent to obtain refresh token during testing
)
    
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    state = session.get('state',None)
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )

    # user the athorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # credentials object (access token, refresh token, id token, etc)
    creds = flow.credentials

    # verify the token and get user info
    request_session = grequests.Request()
    id_info = id_token.verify_oauth2_token(
        creds.id_token, request_session, audience=creds.client_id
    )


    # save minimal user info in session (don't store credentials in session for production)
    session["user"] = {
        "id": id_info.get("sub"),
        "email": id_info.get("email"),
        "name": id_info.get("name"),
        "picture": id_info.get("picture")
    }

    # Save user to DB if not exists
    user = User.query.get(id_info.get("sub"))
    if not user:
        user = User(
            id=id_info.get("sub"),
            name=id_info.get("name"),
            email=id_info.get("email"),
            picture=id_info.get("picture")
        )
        db.session.add(user)
        db.session.commit()

    # OPTIONAL: store tokens somewhere secure if you need to call google APIs later
    # e.g. store creds.token, creds.refresh_token, creds.expiry in DB tied to user.id

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))





if __name__=="__main__":
    app.run(debug=True)
