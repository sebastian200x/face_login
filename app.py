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
import secrets

from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from datetime import datetime, date
import face_recognition
from base64 import b64encode, b64decode
import re

from helpers import apology, login_required

# Configure application
app = Flask(__name__)
app.secret_key = "capstone"

# Configure session to use filesystem (instead of signed cookies)
# app.config["SESSION_FILE_DIR"] = mkdtemp()
# app.config["SESSION_PERMANENT"] = False
# app.config["SESSION_TYPE"] = "filesystem"
# Session(app)

# Configure MySQL database connection
conn = mysql.connector.connect(
    host="localhost",
    database="dbhofin",
    user="root",
    password="",
)

cursor = conn.cursor()

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
    check_delete = conn.cursor()
    check_delete.execute(
        "SELECT * FROM tbl_useracc WHERE user_id=%s AND is_deleted='yes'",
        (session.get("user_id"),),
    )
    result = check_delete.fetchall()

    if len(result) > 0:
        session.clear()
        return redirect(url_for("home"))

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
    check_delete = conn.cursor()
    check_delete.execute(
        "SELECT * FROM tbl_useracc WHERE user_id=%s AND is_deleted='yes'",
        (session.get("user_id"),),
    )
    result = check_delete.fetchall()

    if len(result) > 0:
        session.clear()
        flash("Your account has been deleted. Please login again.", "info")
        return redirect(url_for("home"))

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


def cash_code(length=5):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    while True:
        code = "".join(secrets.choice(alphabet) for i in range(length))
        if not code_exists(code):
            break
    return code


def code_exists(code):
    query = "SELECT COUNT(*) FROM tbl_transaction WHERE code = %s"
    cursor.execute(query, (code,))
    count = cursor.fetchone()[0]
    return count > 0


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

        # Check if user exists
        if user is None:
            return render_template("login.html", messager=3)

        # is user deleted ?
        if user[5] == "no":
            # is user verified ?
            if user[6] == "yes":
                if not bcrypt.checkpw(
                    input_password.encode("utf-8"), user[2].encode("utf-8")
                ):
                    return render_template("login.html", messager=3)

                # Check if user is admin
                if user[4] == "yes":
                    session.clear()
                    session["is_admin"] = "yes"
                    session["fullname"] = str(user[9]) + " " + str(user[11])
                    session["user_id"] = user[0]
                    session["user_type"] = "ADMIN"
                    return redirect(url_for("dashboard"))
                else:
                    session.clear()
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


@app.route("/account")
def account():
    user_type = session.get("user_type")
    if user_type == "ADMIN":
        return redirect(url_for("admin_account"))
    elif user_type == "USER":
        return redirect(url_for("members_account"))
    else:
        return redirect(url_for("login"))


@app.route("/admin/account")
def admin_account():
    id = session.get("user_id")
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            *
        FROM
            tbl_useracc,
            tbl_userinfo
        WHERE
            tbl_useracc.user_id = %s AND tbl_userinfo.user_id = %s
        """,
        (
            id,
            id,
        ),
    )
    admin = cursor.fetchone()

    return adminredirect("/admin/account.html", admin=admin)


@app.route("/members/account")
def members_account():
    id = session.get("user_id")
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            *
        FROM
            tbl_useracc,
            tbl_userinfo,
            tbl_property
        WHERE
            tbl_useracc.user_id = %s AND tbl_userinfo.user_id = %s AND tbl_property.user_id = %s
        """,
        (id, id, id),
    )
    user = cursor.fetchone()

    return memberredirect("/members/account.html", user=user)


@app.route("/admin/dashboard", methods=["GET", "POST"])
def dashboard():

    cursor.execute(
        "SELECT COUNT(*) FROM tbl_useracc WHERE is_admin = 'no' AND is_deleted = 'no' AND is_verified = 'yes'"
    )
    count_user = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM tbl_useracc WHERE is_verified = 'no'")
    to_verify = cursor.fetchone()[0]

    if not to_verify:
        to_verify = 0

    cursor.execute("SELECT COUNT(*) FROM tbl_useracc WHERE is_deleted = 'yes'")
    deleted = cursor.fetchone()[0]

    if not deleted:
        deleted = 0

    cursor.execute("SELECT COUNT(*) FROM tbl_transaction WHERE is_verified = 'no'")
    transac_to_verify = cursor.fetchone()[0]

    if not transac_to_verify:
        transac_to_verify = 0

    cursor.execute(
        "SELECT COUNT(*) FROM tbl_transaction WHERE is_verified = 'yes' AND (transc_type = 'cash' OR transc_type = 'gcash')"
    )
    verified_transac = cursor.fetchone()[0]

    if not transac_to_verify:
        transac_to_verify = 0

    cursor.execute(
        "SELECT COUNT(*) FROM tbl_transaction WHERE transc_type = 'arrangement'"
    )
    unpaid_members = cursor.fetchone()[0]

    if not unpaid_members:
        total_earnings = 0

    cursor.execute(
        """
        SELECT 
            SUM(amount) AS total_amount
        FROM 
            tbl_transaction
        WHERE 
            is_verified = 'yes'
        AND 
            (transc_type = 'cash' OR transc_type = 'gcash')
        AND
            amount IS NOT NULL
        AND 
            date IS NOT NULL
        ;
        """
    )
    total_earnings = cursor.fetchone()[0]
    if total_earnings:
        total_earnings = "{:,}".format(total_earnings)
    else:
        total_earnings = 0

    return adminredirect(
        "admin/dashboard.html",
        count_user=count_user,
        to_verify=to_verify,
        deleted=deleted,
        transac_to_verify=transac_to_verify,
        verified_transac=verified_transac,
        unpaid_members=unpaid_members,
        total_earnings=total_earnings,
    )


@app.route("/admin/members_info", methods=["POST", "GET"])
def admin_members_info():

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


@app.route("/admin/accept/<int:id>", methods=["POST"])
def approve(id):
    try:
        cur = conn.cursor()

        # Update tbl_useracc
        cur.execute(
            "UPDATE tbl_useracc SET is_verified = 'yes' WHERE user_id = %s", (id,)
        )

        # Check if row exists in tbl_property using SELECT query
        cur.execute("SELECT * FROM tbl_property WHERE user_id = %s", (id,))
        existing_row = cur.fetchone()

        # If no row exists, INSERT into tbl_property
        if not existing_row:
            cur.execute("INSERT INTO tbl_property (user_id) VALUES (%s)", (id,))

        conn.commit()

        flash("User approval successful.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error approving user: {str(e)}", "error")
    finally:
        cur.close()
    return redirect(url_for("admin_members_info"))


@app.route("/admin/decline/<int:id>", methods=["POST"])
def decline(id):
    try:
        cur = conn.cursor()

        cur.execute("DELETE FROM tbl_userinfo WHERE user_id = %s", (id,))
        cur.execute("DELETE FROM tbl_useracc WHERE user_id = %s", (id,))

        conn.commit()

        flash("User decline successful.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error declining user: {str(e)}", "error")
    finally:
        cur.close()

    return redirect(url_for("admin_members_info"))


@app.route("/admin/edit_info/<int:id>", methods=["POST", "GET"])
def admin_edit_info(id):
    info = conn.cursor()
    info.execute(
        """
    SELECT *
    FROM tbl_userinfo
    JOIN tbl_property
    ON tbl_userinfo.user_id = %s AND tbl_property.user_id = %s
    LIMIT 1""",
        (id, id),
    )

    info = info.fetchone()

    return adminredirect("/admin/edit_info.html", info=info)


@app.route("/admin/delete_info/<int:id>", methods=["POST", "GET"])
def delete_info(id):
    try:
        delete = conn.cursor()
        delete.execute(
            """
            UPDATE
                tbl_useracc
            SET
                is_deleted = 'yes'
            WHERE
                user_id = %s;
            """,
            (id,),
        )
        conn.commit()
        flash("Account deleted successfully!", "success")
    except Exception as e:
        flash(f"Error deleting account: {str(e)}", "error")
    finally:
        delete.close()

    return redirect(url_for("admin_members_info"))


@app.route("/admin/update_info/<int:id>", methods=["POST", "GET"])
def update_info(id):
    given_name = request.form.get("given_name")
    middle_name = request.form.get("middle_name")
    last_name = request.form.get("last_name")
    gender = request.form.get("gender")
    id_no = request.form.get("id_no")
    blk_no = request.form.get("blk_no")
    lot_no = request.form.get("lot_no")
    homelot_area = request.form.get("homelot_area")
    open_space = request.form.get("open_space")
    sharein_loan = request.form.get("sharein_loan")
    principal_interest = request.form.get("principal_interest")
    MRI = request.form.get("MRI")
    total = request.form.get("total")

    update = conn.cursor()

    try:
        update.execute(
            """
                UPDATE tbl_userinfo
                SET given_name = %s,
                    middle_name = %s,
                    last_name = %s,
                    gender = %s
                WHERE user_id = %s
                """,
            (
                given_name,
                middle_name,
                last_name,
                gender,
                id,
            ),
        )
        update.execute(
            """
            UPDATE tbl_property
            SET id_no = %s,
                blk_no = %s,
                lot_no = %s,
                homelot_area = %s,
                open_space = %s,
                sharein_loan = %s,
                principal_interest = %s,
                MRI = %s,
                total = %s
            WHERE user_id = %s
            """,
            (
                id_no,
                blk_no,
                lot_no,
                homelot_area,
                open_space,
                sharein_loan,
                principal_interest,
                MRI,
                total,
                id,
            ),
        )
        conn.commit()
        update.close()
        flash("Account updated successfully!", "success")
    except Exception as e:
        flash(f"Error updating account: {str(e)}", "error")
    return redirect(url_for("admin_members_info"))


@app.route("/admin/payment_arrangement", methods=["POST", "GET"])
def admin_payment_arrangement():
    new = conn.cursor()
    new.execute(
        """
        SELECT
            tbl_property.*,
            tbl_userinfo.*
        FROM
            tbl_property
        LEFT JOIN tbl_userinfo ON tbl_property.user_id = tbl_userinfo.user_id
        LEFT JOIN tbl_useracc ON tbl_property.user_id = tbl_useracc.user_id
        WHERE
            tbl_userinfo.user_id NOT IN(
            SELECT
                user_id
            FROM
                tbl_transaction
        ) AND tbl_property.total IS NOT NULL AND tbl_useracc.is_admin = 'no' AND tbl_useracc.is_deleted = 'no' AND tbl_useracc.is_verified = 'yes'  
        """
    )
    new = new.fetchall()

    old = conn.cursor()
    old.execute(
        """
        SELECT
            prop.*,
            userinfo.*
        FROM
            tbl_property prop
        LEFT JOIN tbl_userinfo userinfo ON prop.user_id = userinfo.user_id
        LEFT JOIN tbl_useracc useracc ON prop.user_id = useracc.user_id
        WHERE
            userinfo.user_id IN (
                SELECT
                    user_id
                FROM
                    tbl_transaction
                WHERE
                    MONTH(due_date) != MONTH(CURRENT_DATE())
            )
            AND prop.total IS NOT NULL
            AND useracc.is_admin = 'no'
            AND useracc.is_deleted = 'no'
            AND useracc.is_verified = 'yes'
            AND userinfo.user_id NOT IN (
                SELECT
                    user_id
                FROM
                    tbl_transaction
                WHERE
                    transc_type = 'arrangement'
            );
        """
    )
    old = old.fetchall()

    return adminredirect("admin/payment_arrangement.html", new=new, old=old)


@app.route("/admin/payment_arrange/<int:id>", methods=["POST", "GET"])
def admin_payment_arrange(id):
    arranger = conn.cursor()
    arranger.execute(
        """
        SELECT tbl_property.total, tbl_userinfo.*
        FROM tbl_property
        JOIN tbl_userinfo ON tbl_userinfo.user_id = %s AND tbl_property.user_id = %s
        LIMIT 1;
        """,
        (id, id),
    )
    arranger_data = arranger.fetchone()
    return adminredirect(
        "admin/payment_arrange.html", arrange=arranger_data, today=date.today()
    )


@app.route("/admin/payment_arranged/<int:id>", methods=["POST", "GET"])
def admin_payment_arranged(id):
    if request.method == "POST":
        amount = request.form.get("amount")
        due_date_str = request.form.get("due")

        # Parse and format the due date
        try:
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
        except ValueError:
            return "Error: Invalid date format. Please enter the date in YYYY-MM-DD format."

        update = conn.cursor()
        update.execute(
            """
            INSERT INTO `tbl_transaction` (`user_id`, `balance_debt`, `transc_type`,  `due_date`, `is_verified`) 
            VALUES 
            (%s, %s, 'arrangement', %s, 'yes');
            """,
            (id, amount, due_date),
        )
        conn.commit()
        return redirect(url_for("admin_payment_arrangement"))

    return render_template("payment_arranged.html")


@app.route("/admin/payment_verification", methods=["POST", "GET"])
def admin_payment_verification():
    unverified = conn.cursor()
    unverified.execute(
        """
        SELECT
            *
        FROM
            tbl_transaction, tbl_userinfo
        WHERE
            tbl_transaction.transc_type IN ('gcash', 'cash')
            AND tbl_transaction.is_verified = 'no'
            AND (tbl_transaction.code IS NOT NULL OR tbl_transaction.proof IS NOT NULL)
            
            AND tbl_userinfo.user_id = tbl_transaction.transac_id
        """,
    )
    unverified = unverified.fetchall()
    return adminredirect("/admin/payment_verification.html", unverified=unverified)


@app.route("/admin/payment_verify/<int:id>", methods=["POST", "GET"])
def admin_payment_verify(id):
    to_verify = conn.cursor()
    to_verify.execute(
        """
            SELECT
                *
            FROM
                tbl_transaction, tbl_userinfo
            WHERE
                tbl_transaction.transac_id = %s
            AND 
                tbl_userinfo.user_id = tbl_transaction.user_id 
            """,
        (id,),
    )
    to_verify = to_verify.fetchall()

    if request.method == "POST":
        session["payment_id"] = id
        session["member"] = to_verify[0][1]

    return adminredirect("/admin/payment_verify.html", to_verify=to_verify)


@app.route("/admin/payment_verified", methods=["POST", "GET"])
def admin_payment_verified():

    if "member" in session:
        member = session["member"]
    else:
        return redirect("/admin/payment_history")

    if "payment_id" in session:
        id = session["payment_id"]
    else:
        return redirect("/admin/payment_history")

    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM tbl_transaction WHERE transac_id = %s ;
        """,
        (id,),
    )
    data = cursor.fetchone()

    if data:
        sqlbalance = data[2]
        sqlcode = data[8]

        if request.method == "POST":
            amount = int(request.form.get("amount"))

            if amount <= sqlbalance:
                if request.form.get("code") == sqlcode:
                    update_cursor = conn.cursor()
                    update_cursor.execute(
                        """
                        UPDATE tbl_transaction
                        SET is_verified = 'yes',
                        amount = %s,
                        date = NOW()
                        WHERE transac_id = %s
                        """,
                        (
                            amount,
                            id,
                        ),
                    )
                    conn.commit()
                    return redirect("/admin/payment_history")
                else:
                    flash(
                        "Code is incorrect, please check your code and try again.",
                        "error",
                    )
                    return redirect(url_for("admin_payment_verify", id=id))
            else:
                flash(
                    "The amount you entered is greater than the amount of debt, please try again.",
                    "error",
                )
                return redirect(url_for("admin_payment_verify", id=id))

        return redirect("/admin/payment_verify.html")
    else:
        return redirect("/admin/payment_verification.html")


# update_cursor = conn.cursor()
#             update_cursor.execute(
#                 """
#                 UPDATE tbl_transaction
#                 SET is_verified = 'yes',
#                 date = NOW()
#                 WHERE transac_id = %s
#                 """,
#                 (id,),
#             )
#             conn.commit()


@app.route("/admin/payment_history", methods=["POST", "GET"])
def admin_payment_history():
    history = conn.cursor()
    history.execute(
        """
        SELECT tbl_transaction.*, tbl_userinfo.*, tbl_useracc.*
            FROM tbl_transaction
            JOIN tbl_userinfo ON tbl_transaction.user_id = tbl_userinfo.user_id
            JOIN tbl_useracc ON tbl_transaction.user_id = tbl_useracc.user_id
            WHERE tbl_transaction.transc_type != 'arrangement'
            AND tbl_transaction.is_verified = 'yes'
            ORDER BY tbl_transaction.date;
        """
    )
    history = history.fetchall()
    return adminredirect("/admin/payment_history.html", history=history)


@app.route("/admin/view_history/<int:id>", methods=["GET", "POST"])
def admin_view_history(id):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            tbl_transaction.*,
            tbl_userinfo.*
        FROM
            tbl_transaction
        JOIN
            tbl_userinfo ON tbl_userinfo.user_id = tbl_transaction.user_id
        WHERE
            transac_id = %s
        """,
        (id,),
    )
    transaction = cursor.fetchone()
    return adminredirect("/admin/view_history.html", transaction=transaction)


@app.route("/members/home")
def members_home():
    if session.get("payment_id"):
        session.pop("payment_id")
    id = session.get("user_id")

    unpaid_cursor = conn.cursor()
    unpaid_cursor.execute(
        """
        SELECT
            *
        FROM
            tbl_transaction
        WHERE
            amount IS NULL AND DATE IS NULL AND is_verified = 'yes' AND transc_type = 'arrangement' AND user_id = %s;
        """,
        (id,),
    )
    unpaid_cursor.fetchall()
    unpaid_count = unpaid_cursor.rowcount

    payment_cursor = conn.cursor()
    payment_cursor.execute(
        """
        SELECT
            *
        FROM
            tbl_transaction
        WHERE
            user_id = %s;
        """,
        (id,),
    )
    payment_cursor.fetchall()
    payment_count = payment_cursor.rowcount

    return memberredirect(
        "members/home.html", paid_count=payment_count, unpaid_count=unpaid_count
    )


@app.route("/members/payment")
def payment():
    if session.get("payment_id"):
        session.pop("payment_id")

    id = session.get("user_id")
    arranger = conn.cursor()
    arranger.execute(
        """
        SELECT
            *
        FROM
            tbl_transaction
        WHERE
            amount IS NULL AND DATE IS NULL AND is_verified = 'yes' AND transc_type = 'arrangement' AND user_id = %s
        ORDER BY 
            due_date DESC;
        """,
        (id,),
    )
    arranger_data = arranger.fetchall()

    return memberredirect("members/payment.html", arranger=arranger_data)


@app.route("/members/pay/<int:payment_id>", methods=["POST", "GET"])
def members_pay(payment_id):
    if session.get("payment_id"):
        session.pop("payment_id")
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT 
            transac_id 
        FROM 
            tbl_transaction
        WHERE 
            transac_id = %s
        """,
        (payment_id,),
    )
    result = cursor.fetchone()
    conn.commit()
    if not result:
        return redirect(url_for("payment"))
    else:
        session["payment_id"] = payment_id
        return memberredirect("members/pay.html")


@app.route("/choice", methods=["POST"])
def choice():
    choice = request.form["choice"]
    if choice == "cash":
        code = cash_code()
        session["code"] = code
        return redirect(url_for("members_payment_cash"))
    else:
        return redirect(url_for("members_payment_gcash"))


@app.route("/members/payment_cash", methods=["POST", "GET"])
def members_payment_cash():

    if session.get("payment_id"):
        payment_id = session.get("payment_id")
    else:
        return redirect(url_for("payment"))

    id = session.get("user_id")

    payment = conn.cursor()
    payment.execute(
        """
        SELECT
            *
        FROM
            tbl_transaction
        WHERE transac_id = %s AND user_id = %s;
        """,
        (
            payment_id,
            id,
        ),
    )
    payment_data = payment.fetchall()

    code = session.get("code")

    if request.method == "POST":
        code_confirm = request.form.get("code-confirm")
        if code_confirm == code:
            try:
                cash_proceed = conn.cursor()
                cash_proceed.execute(
                    """
                    UPDATE 
                        tbl_transaction 
                    SET 
                        code = %s,
                        transc_type = 'Cash',
                        is_verified = 'no'
                    WHERE 
                        transac_id = %s 
                    AND 
                        user_id = %s;
                    """,
                    (
                        code,
                        payment_id,
                        id,
                    ),
                )
                conn.commit()
            except Exception as e:
                print(e)
                return render_template("error.html", error=e)

            return redirect(url_for("members_payment_history"))
        else:
            return memberredirect("members/payment_cash.html", message=1)

    return memberredirect("members/payment_cash.html", cash=payment_data, code=code)


@app.route("/members/payment_gcash", methods=["POST", "GET"])
def members_payment_gcash():
    if session.get("payment_id"):
        payment_id = session.get("payment_id")
    else:
        return redirect(url_for("payment"))

    id = session.get("user_id")

    payment = conn.cursor()
    payment.execute(
        """
        SELECT
            *
        FROM
            tbl_transaction
        WHERE transac_id = %s AND user_id = %s;
        """,
        (
            payment_id,
            id,
        ),
    )
    payment_data = payment.fetchall()

    return memberredirect("members/payment_gcash.html", gcash=payment_data)


@app.route("/members/upload_proof", methods=["POST", "GET"])
def members_upload_proof():
    amount = request.form.get("amount")
    if "proof" in request.files:
        file = request.files["proof"]
        if file.filename != "":
            payment_id = session.get("payment_id")
            if not payment_id:
                flash("Payment ID not found.", "error")
                return redirect(url_for("payment"))

            directory = "./static/proof/"
            sql_directory = "./proof/"

            filename = secure_filename(f"{payment_id}.jpg")
            file.save(os.path.join(directory, filename))
            directory_path = os.path.join(sql_directory, filename)

            now = datetime.now()
            sql_now = now.strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute(
                "UPDATE tbl_transaction SET proof = %s, date = %s, transc_type = 'Gcash', is_verified = 'no', amount = %s WHERE transac_id = %s",
                (directory_path, sql_now, amount, payment_id),
            )
            conn.commit()
            flash("Proof uploaded successfully.", "success")
            return redirect(url_for("members_payment_history"))

    flash("No file selected or invalid file format.", "error")
    return redirect(url_for("members_payment_history"))


@app.route("/members/payment_history", methods=["POST", "GET"])
def members_payment_history():
    if session.get("payment_id"):
        session.pop("payment_id")

    id = session.get("user_id")

    unverified = conn.cursor()
    unverified.execute(
        """
        SELECT
            *
        FROM
            tbl_transaction
        WHERE
            transc_type IN ('gcash', 'Cash')
            AND user_id = %s
            AND is_verified = 'no'
            AND (code IS NOT NULL OR proof IS NOT NULL)
        """,
        (id,),
    )
    unverified = unverified.fetchall()

    verified = conn.cursor()
    verified.execute(
        """
        SELECT
            *
        FROM
            tbl_transaction
        WHERE
            transc_type IN ('gcash', 'cash')
            AND user_id = %s 
            AND is_verified = 'yes' 
            AND (code IS NOT NULL OR proof IS NOT NULL)
        """,
        (id,),
    )
    verified = verified.fetchall()

    return memberredirect(
        "/members/payment_history.html", unverified=unverified, verified=verified
    )


@app.route("/members/view_history/<int:id>", methods=["POST"])
def members_view_history(id):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            tbl_transaction.*,
            tbl_userinfo.*
        FROM
            tbl_transaction
        JOIN
            tbl_userinfo ON tbl_userinfo.user_id = tbl_transaction.user_id
        WHERE
            transac_id = %s
        """,
        (id,),
    )
    transaction = cursor.fetchone()
    return memberredirect("/members/view_history.html", transaction=transaction)


@app.route("/members/view_proof/<int:id>", methods=["POST", "GET"])
def members_view_proof(id):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            proof
        FROM
            tbl_transaction
        WHERE
            transac_id = %s
        """,
        (id,),
    )
    proof = cursor.fetchone()
    return memberredirect("/members/view_proof.html", proof=proof)


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
            # face is not yet registered
            return render_template("face_login.html", message=5)

        unknown_image = face_recognition.load_image_file(
            "./static/face/unknown/" + str(id_) + ".jpg"
        )
        try:
            unknown_face_encoding = face_recognition.face_encodings(unknown_image)[0]
        except:
            # face is not clear
            return render_template("face_login.html", message=2)

        results = face_recognition.compare_faces(
            [bill_face_encoding], unknown_face_encoding
        )

        if results[0]:

            cursor.execute("SELECT * FROM tbl_useracc WHERE username = %s", (username,))
            user = cursor.fetchone()
            if user is not None:

                userid = user[0]

                cursor.execute(
                    "SELECT * FROM tbl_useracc, tbl_userinfo WHERE tbl_useracc.user_id = %s AND tbl_useracc.user_id = tbl_userinfo.user_id",
                    (userid,),
                )
                user = cursor.fetchone()
                # is user deleted ?
                if user[5] == "no":
                    # is user verified ?
                    if user[6] == "yes":
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
                        return userchecker("face_login.html", messager=4)
                else:
                    return userchecker("face_login.html", messager=5)

            else:
                return userchecker(
                    "face_login.html", message=4
                )  # username if not found in database
        else:
            return userchecker("face_login.html", message=3)  # Face recognition failed

    else:
        return userchecker("face_login.html")


@app.route("/test", methods=["GET", "POST"])
def test():
    return render_template("test.html")


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
    app.run(debug=True, host="localhost", port=6969)


# to make it accessible to other device in the same network use this:
# flask run --host=0.0.0.0
# pip freeze > requirements.txt
