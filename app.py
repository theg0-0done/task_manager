from werkzeug.security import check_password_hash
from flask import Flask, flash, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import secrets
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Set secret key (make sure to use a secure, random string for production)
app.secret_key = secrets.token_hex(16)  # For example, 16-byte secure keyDATABASE = "project.db"

# Database connection helper


def get_db():
    """
    Establishes a connection to the project.db SQLite database and returns the connection object.
    """
    conn = sqlite3.connect("project.db")  # Connect to the database
    conn.row_factory = sqlite3.Row       # Enable row-based access (dictionary-like behavior)
    return conn

# Route for the home page


@app.route("/index")
def index():
    return render_template("index.html")


@app.route("/error")
def error():
    return render_template("error.html")


# Route for the login page
@app.route("/")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validation
        if not username:
            return render_template("error.html", message="Must provide username.")
        elif not password:
            return render_template("error.html", message="Must provide password.")

        # Database query to fetch user details by username
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()  # Fetch one matching record
        conn.close()

        # Check if user exists and password is correct
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]  # Store the user_id in the session
            flash(f"You're logged in as '{username}'!", "success")
            return redirect(url_for("index"))  # Redirect to index on successful login
        else:
            return render_template("error.html", message="Invalid username or password.")

    # Render the login form for GET requests
    return render_template("login.html")

# Route for register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validation
        if not username:
            return render_template("error.html", message="Username is required.")
        elif not password:
            return render_template("error.html", message="Password is required.")
        elif not confirm_password:
            return render_template("error.html", message="Password Confirmation is required.")
        elif password != confirm_password:
            return render_template("error.html", message="Passwords must match.")

        hashed_password = generate_password_hash(password)
        # Insert user into the database
        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            conn.commit()  # Save changes
            conn.close()
            return redirect(url_for("login"))  # Redirect to login on successful registration
        except sqlite3.IntegrityError:
            return render_template("error.html", message="Username already exists.")

    # Render register page if GET request
    return render_template("register.html")


# Route to change password
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")  # Current password
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Validation
        if not password:
            return render_template("error.html", message="Current password is required.")
        elif not new_password:
            return render_template("error.html", message="New password is required.")
        elif not confirm_password:
            return render_template("error.html", message="Password confirmation is required.")
        elif password == new_password:
            return render_template("error.html", message="New password must not match the current password.")
        elif new_password != confirm_password:
            return render_template("error.html", message="Passwords must match.")

        # Fetch the user's current hashed password from the database
        conn = get_db()
        user = conn.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not user or not check_password_hash(user["password"], password):
            # Current password is incorrect
            return render_template("error.html", message="Invalid current password.")

        # Hash the new password
        hashed_new_password = generate_password_hash(new_password)

        # Update the password in the database (use the hashed version of the current password for comparison)
        result = conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (hashed_new_password, username)
        )
        conn.commit()
        conn.close()

        if result.rowcount == 0:
            return render_template("error.html", message="Password change failed.")

        # Flash success message
        flash("Password changed successfully!", "success")

        # Redirect to the home page after a successful password change
        return redirect(url_for("index"))

    return render_template("change_password.html")


# Route to change password
@app.route("/personal", methods=["GET", "POST"])
def personal():
    if request.method == "POST":
        # Check if it's an AJAX request (JSON data)
        if request.is_json:
            data = request.get_json()

            # Extract task data from the request
            task_name = data['task_name']
            task_type = data['task_type']
            deadline = data['deadline']
            description = data['description']
            done = data['done']

            # Get the user_id from the session
            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"status": "error", "message": "User not logged in"})

            # Save the task to the database, associating it with the user
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO tasks (user_id, done, task_name, task_type, deadline, description, type)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (user_id, done, task_name, task_type, deadline, description, 'personal'))
            conn.commit()

            # Send back a success response
            return jsonify({"status": "success", "message": "Task saved successfully"})

    # Fetch tasks only for the logged-in user
    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND type = 'personal'", (user_id,))
        tasks = cursor.fetchall()
        return render_template("personal.html", tasks=tasks)

    return render_template("personal.html")


@app.route("/work", methods=["GET", "POST"])
def work():
    if request.method == "POST":
        # Check if it's an AJAX request (JSON data)
        if request.is_json:
            data = request.get_json()

            # Extract task data from the request
            task_name = data['task_name']
            task_type = data['task_type']
            deadline = data['deadline']
            description = data['description']
            done = data['done']

            # Get the user_id from the session
            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"status": "error", "message": "User not logged in"})

            # Save the task to the database, associating it with the user
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO tasks (user_id, done, task_name, task_type, deadline, description, type)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (user_id, done, task_name, task_type, deadline, description, 'work'))
            conn.commit()

            # Send back a success response
            return jsonify({"status": "success", "message": "Task saved successfully"})

    # Fetch tasks only for the logged-in user
    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND type = 'work'", (user_id,))
        tasks = cursor.fetchall()
        return render_template("work.html", tasks=tasks)

    return render_template("work.html")


@app.route("/study", methods=["GET", "POST"])
def study():
    if request.method == "POST":
        # Check if it's an AJAX request (JSON data)
        if request.is_json:
            data = request.get_json()

            # Extract task data from the request
            task_name = data['task_name']
            task_type = data['task_type']
            deadline = data['deadline']
            description = data['description']
            done = data['done']

            # Get the user_id from the session
            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"status": "error", "message": "User not logged in"})

            # Save the task to the database, associating it with the user
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO tasks (user_id, done, task_name, task_type, deadline, description, type)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (user_id, done, task_name, task_type, deadline, description, 'study'))
            conn.commit()

            # Send back a success response
            return jsonify({"status": "success", "message": "Task saved successfully"})

    # Fetch tasks only for the logged-in user
    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND type = 'study'", (user_id,))
        tasks = cursor.fetchall()
        return render_template("study.html", tasks=tasks)

    return render_template("study.html")


@app.route("/else", methods=["GET", "POST"])
def alse():
    if request.method == "POST":
        # Check if it's an AJAX request (JSON data)
        if request.is_json:
            data = request.get_json()

            # Extract task data from the request
            task_name = data['task_name']
            task_type = data['task_type']
            deadline = data['deadline']
            description = data['description']
            done = data['done']

            # Get the user_id from the session
            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"status": "error", "message": "User not logged in"})

            # Save the task to the database, associating it with the user
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO tasks (user_id, done, task_name, task_type, deadline, description, type)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (user_id, done, task_name, task_type, deadline, description, 'else'))
            conn.commit()

            # Send back a success response
            return jsonify({"status": "success", "message": "Task saved successfully"})

    # Fetch tasks only for the logged-in user
    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND type = 'else'", (user_id,))
        tasks = cursor.fetchall()
        return render_template("else.html", tasks=tasks)

    return render_template("else.html")


@app.route("/logout")
def logout():
    session.clear()  # Clear the session
    return redirect(url_for("login"))  # Redirect to the login page


if __name__ == "__main__":
    app.run(debug=True)
