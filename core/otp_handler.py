import random
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from core.config import settings

logger = logging.getLogger(settings.APP_NAME)


def generate_otp() -> str:
    """Generate a numeric OTP of length settings.OTP_LENGTH (default 6 digits)."""
    digits = "0123456789"
    return "".join(random.choice(digits) for _ in range(settings.OTP_LENGTH))


def send_otp_email(email: str, otp: str, purpose: str) -> None:
    """
    Sends the OTP via real Gmail SMTP. Falls back to console logging if sending fails,
    so registration/forgot-password flows are never blocked by a transient email issue.
    """
    subject = "Verify your account - OTP Code" if purpose == "registration" else "Reset your password - OTP Code"

    body_html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Your OTP Code</h2>
        <p>Use the code below to {"verify your account" if purpose == "registration" else "reset your password"}:</p>
        <h1 style="color: #2563eb; letter-spacing: 4px;">{otp}</h1>
        <p>This code is valid for {settings.OTP_TOKEN_EXPIRE_MINUTES} minutes.</p>
        <p style="color: #888; font-size: 12px;">If you did not request this, please ignore this email.</p>
      </body>
    </html>
    """

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.SMTP_FROM_EMAIL
    message["To"] = email
    message.attach(MIMEText(body_html, "html"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM_EMAIL, email, message.as_string())
        logger.info(f"OTP email sent successfully to {email} (purpose: {purpose})")
        print(f"OTP email sent successfully to {email} - check the inbox!")
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email}: {e}")
        print(f"\n{'='*50}\n[EMAIL SEND FAILED - FALLBACK LOG]\nTo: {email}\nOTP: {otp}\nError: {e}\n{'='*50}\n")