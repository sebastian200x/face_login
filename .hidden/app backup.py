import os
import re
import io
import zlib
from werkzeug.utils import secure_filename
from flask import Response
import mysql.connector
from mysql.connector import Error
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import bcrypt

from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from datetime import datetime
import face_recognition
from base64 import b64encode, b64decode
import re

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure MySQL database connection
try:
    conn = mysql.connector.connect(
        host="localhost",
        database="face_login",
        user="root",
        password="",
    )
    cursor = conn.cursor()
except Error as e:
    print(e)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter


@app.route("/")
@login_required
def home():
    return redirect("/home")


@app.route("/home")
@login_required
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        input_username = request.form.get("username")
        input_password = request.form.get("password")

        if not input_username:
            return render_template("login.html", messager=1)
        elif not input_password:
            return render_template("login.html", messager=2)

        cursor.execute("SELECT * FROM users WHERE username = %s", (input_username,))
        user = cursor.fetchone()

        if user is None or not bcrypt.checkpw(
            input_password.encode("utf-8"), user[2].encode("utf-8")
        ):
            return render_template("login.html", messager=3)

        session["user_id"] = user[0]
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        input_username = request.form.get("username")
        input_password = request.form.get("password")
        input_confirmation = request.form.get("confirmation")

        if not input_username:
            return render_template("register.html", messager=1)
        elif not input_password:
            return render_template("register.html", messager=2)
        elif not input_confirmation:
            return render_template("register.html", messager=4)
        elif not input_password == input_confirmation:
            return render_template("register.html", messager=3)

        cursor.execute(
            "SELECT username FROM users WHERE username = %s", (input_username,)
        )
        username = cursor.fetchone()

        if username is not None:
            return render_template("register.html", messager=5)
        else:
            hashed_password = bcrypt.hashpw(
                input_password.encode("utf-8"), bcrypt.gensalt()
            )
            cursor.execute(
                "INSERT INTO users (username, hash) VALUES (%s, %s)",
                (input_username, hashed_password.decode("utf-8")),
            )
            conn.commit()
            flash(f"Registered as {input_username}")
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/facereg", methods=["GET", "POST"])
def facereg():
    session.clear()
    if request.method == "POST":
        encoded_image = (request.form.get("pic") + "==").encode("utf-8")
        username = request.form.get("name")

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        name = cursor.fetchone()

        if name is None:
            return render_template("camera.html", message=1)

        id_ = name[0]
        compressed_data = zlib.compress(encoded_image, 9)
        uncompressed_data = zlib.decompress(compressed_data)
        decoded_data = b64decode(uncompressed_data)

        with open(
            "./static/face/unknown/" + str(id_) + ".jpg", "wb"
        ) as new_image_handle:
            new_image_handle.write(decoded_data)

        try:
            image_of_bill = face_recognition.load_image_file(
                "./static/face/" + str(id_) + ".jpg"
            )
            bill_face_encoding = face_recognition.face_encodings(image_of_bill)[0]
        except:
            return render_template("camera.html", message=5)

        unknown_image = face_recognition.load_image_file(
            "./static/face/unknown/" + str(id_) + ".jpg"
        )
        try:
            unknown_face_encoding = face_recognition.face_encodings(unknown_image)[0]
        except:
            return render_template("camera.html", message=2)

        results = face_recognition.compare_faces(
            [bill_face_encoding], unknown_face_encoding
        )

        if results[0]:
            cursor.execute("SELECT * FROM users WHERE username = %s", ("swa",))
            username_sw = cursor.fetchone()
            if username_sw is not None:
                session["user_id"] = username_sw[0]
                return redirect("/")
            else:
                return render_template("camera.html", message=4)  # User 'swa' not found
        else:
            return render_template("camera.html", message=3)  # Face recognition failed

    else:
        return render_template("camera.html")


@app.route("/facesetup", methods=["GET", "POST"])
def facesetup():
    if request.method == "POST":
        encoded_image = (request.form.get("pic") + "==").encode("utf-8")
        id_ = session["user_id"]

        compressed_data = zlib.compress(encoded_image, 9)
        uncompressed_data = zlib.decompress(compressed_data)
        decoded_data = b64decode(uncompressed_data)

        with open("./static/face/" + str(id_) + ".jpg", "wb") as new_image_handle:
            new_image_handle.write(decoded_data)

        try:
            image_of_bill = face_recognition.load_image_file(
                "./static/face/" + str(id_) + ".jpg"
            )
            bill_face_encoding = face_recognition.face_encodings(image_of_bill)[0]
        except:
            return render_template("face.html", message=1)

        return redirect("/home")

    else:
        return render_template("face.html")


def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return render_template("error.html", e=e)


for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == "__main__":
    app.run()
