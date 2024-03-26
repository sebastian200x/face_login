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
        database="dbhofin",
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


def logincheck(template, **args):
    is_admin = session.get("user_id")
    if is_admin is None:
        return redirect(url_for("home"))
    else:
        return render_template(template, **args)


# session checker if logged in it will redirect to respective homepage
def userchecker(dir, **args):
    is_admin = session.get("is_admin")
    if is_admin == "yes":
        return redirect(url_for("dashboard"))
    elif is_admin == "no":
        return redirect(url_for("members_home"))
    else:
        return render_template(dir, **args)


def adminredirect(dir, **args):
    is_admin = session.get("is_admin")
    if is_admin is not None:
        if is_admin == "no":
            return redirect(url_for("members_home"))
        else:
            return render_template(dir, **args)
    else:
        return redirect(url_for("login"))


def memberredirect(dir, **args):
    is_admin = session.get("is_admin")
    if is_admin is not None:
        if is_admin == "yes":
            return redirect(url_for("dashboard"))
        else:
            return render_template(dir, **args)
    else:
        return redirect(url_for("login"))


# username generator
def generate_username(id):
    now = datetime.now()
    year_today = now.strftime("%Y")
    username = year_today + str(id)
    return username


# List of Session
@app.route("/sessions")
def active_sessions():
    session_data = []
    for key, value in session.items():
        session_data.append(f"{key}: {value}")
    return "\n".join(session_data)


# Custom filter


@app.route("/")
def home():
    return redirect("/home")


@app.route("/home")
def index():
    # Temporary admin account for 1st time opened

    # reset the database and reload the website for first time use
    admin_username = "admin"
    admin_password = "admin"
    hashed_admin_password = bcrypt.hashpw(
        admin_password.encode("utf-8"), bcrypt.gensalt()
    )

    is_admin = "yes"
    is_deleted = "no"
    is_verified = "yes"

    create = conn.cursor()
    create.execute("SELECT * FROM tbl_useracc WHERE is_admin='yes' AND is_deleted='no'")
    result = create.fetchall()
    if len(result) == 0:
        create.execute(
            "INSERT INTO `tbl_useracc`(`username`, `password`, `is_admin`, `is_deleted`, `is_verified`) VALUES (%s,%s,%s,%s,%s)",
            (admin_username, hashed_admin_password, is_admin, is_deleted, is_verified),
        )
        create.execute(
            "INSERT INTO `tbl_userinfo`(`user_id`, `given_name`) VALUES ('1','Admin')"
        )
        conn.commit()
        create.close()
    return userchecker("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        input_username = request.form.get("username")
        input_password = request.form.get("password")

        if not input_username:
            return render_template("login.html", messager=1)
        elif not input_password:
            return render_template("login.html", messager=2)

        cursor.execute(
            "SELECT * FROM tbl_useracc, tbl_userinfo WHERE tbl_useracc.username = %s AND tbl_useracc.user_id = tbl_userinfo.user_id",
            (input_username,),
        )
        user = cursor.fetchone()
        # is user deleted ?
        if user[5] == "no":
            # is user verified ?
            if user[6] == "yes":
                if user is None or not bcrypt.checkpw(
                    input_password.encode("utf-8"), user[2].encode("utf-8")
                ):
                    return render_template("login.html", messager=3)

                # Check if user is admin
                if user[4] == "yes":
                    session["is_admin"] = "yes"
                    session["fullname"] = str(user[9]) + " " + str(user[11])
                    session["user_id"] = user[0]
                    session["user_type"] = "ADMIN"
                    return redirect(url_for("dashboard"))
                else:
                    session["is_admin"] = "no"
                    session["fullname"] = str(user[9]) + " " + str(user[11])
                    session["user_id"] = user[0]
                    session["user_type"] = "USER"
                    return redirect(url_for("members_home"))
            else:
                return userchecker("login.html", messager=4)
        else:
            return userchecker("login.html", messager=5)
    else:
        return userchecker("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    last = conn.cursor()
    last.execute("SELECT user_id FROM tbl_useracc ORDER BY user_id DESC LIMIT 1")
    last_row = last.fetchone()
    if last_row:
        next_id = last_row[0] + 1
    else:
        next_id = 1
    last.close()

    username = generate_username(next_id)
    if request.method == "POST":
        given_name = request.form["given_name"].capitalize()
        middle_name = request.form["middle_name"].capitalize()
        last_name = request.form["last_name"].capitalize()

        gender = request.form["gender"].capitalize()

        password = request.form["password"]
        confirm_password = request.form["confirm"]
        email = request.form["email"]

        if not password:
            return render_template("register.html", messager=2)
        elif not confirm_password:
            return render_template("register.html", messager=3)
        elif not password == confirm_password:
            return render_template("register.html", messager=4)
        else:
            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO tbl_useracc (username, password, email) VALUES (%s, %s, %s)",
                (username, hashed_password.decode("utf-8"), email),
            )
            id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO tbl_userinfo (user_id, given_name, middle_name, last_name, gender) VALUES (%s, %s, %s, %s, %s)",
                (id, given_name, middle_name, last_name, gender),
            )
            conn.commit()
            return render_template("login.html", messager="success")
    return render_template("register.html", username=username)


@app.route("/admin/dashboard", methods=["GET", "POST"])
def dashboard():
    cursor.execute(
        "SELECT COUNT(*) FROM tbl_useracc WHERE is_admin = 'no' AND is_deleted = 'no' AND is_verified = 'yes'"
    )
    count_user = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM tbl_useracc WHERE is_verified = 'no'")
    to_verify = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM tbl_useracc WHERE is_deleted = 'yes'")
    deleted = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM tbl_useracc WHERE is_admin = 'no'")
    transac_to_verify = cursor.fetchone()[0]

    return adminredirect(
        "admin/dashboard.html",
        count_user=count_user,
        to_verify=to_verify,
        deleted=deleted,
        transac_to_verify=transac_to_verify,
    )


@app.route("/admin/members_info", methods=["POST", "GET"])
def admin_members_info():
    # inc.execute(
    #     "SELECT * FROM tbl_property, tbl_useracc, tbl_userinfo WHERE tbl_property.blk_no IS NULL AND tbl_property.lot_no IS NULL AND tbl_property.homelot_area IS NULL AND tbl_property.open_space IS NULL AND tbl_property.sharein_loan IS NULL AND tbl_property.principal_interest IS NULL AND tbl_property.MRI IS NULL AND tbl_property.total IS NULL AND tbl_useracc.is_admin = 'no' AND tbl_useracc.is_deleted = 'no';"
    # )

    unv = conn.cursor()
    unv.execute(
        """
        SELECT *
        FROM tbl_useracc, tbl_userinfo 
        WHERE tbl_useracc.user_id = tbl_userinfo.user_id
            AND is_verified = "no"
            AND is_admin = "no"
            AND is_deleted = "no"
        ORDER BY last_name ASC;
        """
    )
    unv = unv.fetchall()

    inc = conn.cursor()
    inc.execute(
        """
    SELECT *
    FROM tbl_property
    JOIN tbl_userinfo ON tbl_property.user_id = tbl_userinfo.user_id
    JOIN tbl_useracc ON tbl_property.user_id = tbl_useracc.user_id
    WHERE is_admin = "no" 
        AND is_deleted = "no"
        AND is_verified = "yes"
        AND (blk_no IS NULL 
        OR lot_no IS NULL 
        OR homelot_area IS NULL 
        OR open_space IS NULL 
        OR sharein_loan IS NULL 
        OR principal_interest IS NULL 
        OR MRI IS NULL 
        OR total IS NULL)
        """
    )
    inc = inc.fetchall()

    complete = conn.cursor()
    complete.execute(
        """
    SELECT *
    FROM tbl_property
    JOIN tbl_userinfo 
    JOIN tbl_useracc 
    ON tbl_property.user_id = tbl_userinfo.user_id AND tbl_property.user_id = tbl_useracc.user_id
    WHERE is_admin = "no" 
        AND is_deleted = "no"
        AND is_verified = "yes"
        AND blk_no IS NOT NULL
        AND lot_no IS NOT NULL
        AND homelot_area IS NOT NULL
        AND open_space IS NOT NULL
        AND sharein_loan IS NOT NULL
        AND principal_interest IS NOT NULL
        AND MRI IS NOT NULL
        AND total IS NOT NULL
        """
    )
    complete = complete.fetchall()

    return adminredirect(
        "/admin/members_info.html", inc=inc, complete=complete, unv=unv
    )


@app.route("/admin/payment_history", methods=["POST", "GET"])
def admin_payment_history():
    history = conn.cursor()
    history.execute(
        """
        SELECT tbl_transaction.*, tbl_userinfo.*
        FROM tbl_transaction
        JOIN tbl_userinfo ON tbl_userinfo.user_id = tbl_transaction.user_id
        WHERE tbl_transaction.transc_type != 'reminder'
        ORDER BY tbl_transaction.date;
        """
    )
    history = history.fetchall()
    return adminredirect("/admin/payment_history.html", history=history)


@app.route("/memebers/home")
def members_home():

    return memberredirect("members/home.html")


@app.route("/facelogin", methods=["GET", "POST"])
def facelogin():
    if request.method == "POST":
        encoded_image = (request.form.get("pic") + "==").encode("utf-8")
        username = request.form.get("username")

        cursor.execute("SELECT * FROM tbl_useracc WHERE username = %s", (username,))
        name = cursor.fetchone()

        if name is None:
            return render_template("face_login.html", message=1)

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
            return render_template("face_login.html", message=5)

        unknown_image = face_recognition.load_image_file(
            "./static/face/unknown/" + str(id_) + ".jpg"
        )
        try:
            unknown_face_encoding = face_recognition.face_encodings(unknown_image)[0]
        except:
            return render_template("face_login.html", message=2)

        results = face_recognition.compare_faces(
            [bill_face_encoding], unknown_face_encoding
        )

        if results[0]:
            cursor.execute("SELECT * FROM tbl_useracc WHERE username = %s", ("admin",))
            username_admin = cursor.fetchone()
            if username_admin is not None:
                session["user_id"] = username_admin[0]
                return redirect("/")
            else:
                return render_template(
                    "face_login.html", message=4
                )  # User 'admin' not found
        else:
            return render_template(
                "face_login.html", message=3
            )  # Face recognition failed

    else:
        return render_template("face_login.html")


@app.route("/faceregister", methods=["GET", "POST"])
def faceregister():
    if request.method == "POST":
        encoded_image = (request.form.get("pic") + "==").encode("utf-8")
        id_ = session.get("user_id")  # Get user ID from session

        compressed_data = zlib.compress(encoded_image, 9)
        uncompressed_data = zlib.decompress(compressed_data)
        decoded_data = b64decode(uncompressed_data)

        with open("./static/face/" + str(id_) + ".jpg", "wb") as new_image_handle:
            new_image_handle.write(decoded_data)

        try:
            image_of_user = face_recognition.load_image_file(
                "./static/face/" + str(id_) + ".jpg"
            )
            user_face_encoding = face_recognition.face_encodings(image_of_user)[0]
            # Store the face encoding in the database or session as needed
        except:
            # Handle if face recognition fails or image is not clear
            return logincheck("face_register.html", message=1)

        return redirect("/home")

    return logincheck("face_register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return render_template("error.html", e=e)


for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == "__main__":
    app.run(debug=True, port="5696")
