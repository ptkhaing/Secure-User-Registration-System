import re
import bcrypt
import random
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import smtplib
from email.message import EmailMessage
import json
import os

# Load user_db from file
if os.path.exists("user_db.json"):
    with open("user_db.json", "r") as f:
        user_db = json.load(f)
else:
    user_db = {}

# Password strength checker
def check_password_strength(password):
    length = len(password) >= 8
    upper = re.search(r"[A-Z]", password)
    lower = re.search(r"[a-z]", password)
    digit = re.search(r"\d", password)
    special = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    score = sum([length, bool(upper), bool(lower), bool(digit), bool(special)])
    if score <= 2:
        return "Weak"
    elif score == 3 or score == 4:
        return "Moderate"
    else:
        return "Strong"

# CAPTCHA
def generate_captcha():
    a, b = random.randint(1, 9), random.randint(1, 9)
    return f"{a} + {b}", a + b

# MFA code
def generate_mfa_code():
    return str(random.randint(100000, 999999))

# Send MFA via Mailtrap
def send_mfa_email(to_email, code):
    msg = EmailMessage()
    msg.set_content(f"Your MFA code is: {code}")
    msg["Subject"] = "Your Secure Registration MFA Code"
    msg["From"] = "noreply@secure-app.com"
    msg["To"] = to_email

    with smtplib.SMTP("sandbox.smtp.mailtrap.io", 2525) as server:
        server.login("be96899c264810", "5d13a18acbd1e6")
        server.send_message(msg)

# Audit log
def log_event(event):
    with open("audit_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()} - {event}\n")

# Save user_db to file
def save_user_data():
    with open("user_db.json", "w") as f:
        json.dump(user_db, f)

# GUI App
class RegistrationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Registration System")

        self.username_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.captcha_input_var = tk.StringVar()
        self.mfa_input_var = tk.StringVar()

        self.password_var.trace_add("write", self.update_strength_label)

        self.captcha_question, self.captcha_answer = generate_captcha()
        self.mfa_code = ""

        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="Username:").pack()
        tk.Entry(self.root, textvariable=self.username_var).pack()

        tk.Label(self.root, text="Email:").pack()
        tk.Entry(self.root, textvariable=self.email_var).pack()

        tk.Label(self.root, text="Password:").pack()
        tk.Entry(self.root, textvariable=self.password_var, show='*').pack()

        self.strength_label = tk.Label(self.root, text="")
        self.strength_label.pack()

        tk.Label(self.root, text=f"CAPTCHA: {self.captcha_question}").pack()
        tk.Entry(self.root, textvariable=self.captcha_input_var).pack()

        tk.Button(self.root, text="Register", command=self.register).pack()

        tk.Label(self.root, text="Enter MFA Code sent to your email:").pack()
        self.mfa_entry = tk.Entry(self.root, textvariable=self.mfa_input_var)
        self.mfa_entry.pack()
        self.mfa_button = tk.Button(self.root, text="Verify MFA", command=self.verify_mfa)
        self.mfa_button.pack()

    def update_strength_label(self, *args):
        password = self.password_var.get()
        strength = check_password_strength(password)
        self.strength_label.config(text=f"Password Strength: {strength}")

    def register(self):
        username = self.username_var.get()
        email = self.email_var.get()
        password = self.password_var.get()
        captcha_input = self.captcha_input_var.get()

        if not re.match("^[a-zA-Z0-9_]{5,}$", username):
            messagebox.showerror("Error", "Username must be at least 5 characters and contain only letters, numbers, or underscores.")
            return

        if username in user_db:
            messagebox.showerror("Error", "Username already exists.")
            return

        strength = check_password_strength(password)
        self.strength_label.config(text=f"Password Strength: {strength}")

        if strength == "Weak":
            messagebox.showerror("Error", "Please choose a stronger password.")
            return

        try:
            if int(captcha_input) != self.captcha_answer:
                messagebox.showerror("Error", "Incorrect CAPTCHA answer.")
                return
        except ValueError:
            messagebox.showerror("Error", "CAPTCHA must be a number.")
            return

        self.hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.final_username = username
        self.final_email = email

        self.mfa_code = generate_mfa_code()
        send_mfa_email(self.final_email, self.mfa_code)
        messagebox.showinfo("MFA Sent", f"An MFA code has been sent to {self.final_email}. Please enter it below.")

    def verify_mfa(self):
        if self.mfa_input_var.get() == self.mfa_code:
            user_db[self.final_username] = self.hashed_pw.decode('utf-8')
            save_user_data()
            log_event(f"Account created: {self.final_username} (MFA verified)")
            messagebox.showinfo("Success", "Account created successfully with MFA!")
            self.root.destroy()
        else:
            messagebox.showerror("Error", "Incorrect MFA code.")

if __name__ == "__main__":
    root = tk.Tk()
    app = RegistrationApp(root)
    root.mainloop()