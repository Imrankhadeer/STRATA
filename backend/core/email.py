import email.message
import logging
import smtplib
from typing import Optional, List, Dict, Any
from backend.config import settings

logger = logging.getLogger("cyber_engine.email")


class EmailDeliveryService:
    """
    Pluggable multi-provider email delivery service for Ternline.
    Supports:
    - AWS SES (production on AWS)
    - Standard SMTP (RFC 5321 / STARTTLS)
    - Memory/Logger mode (development, automated testing, or offline environments)
    """

    def __init__(self):
        self._sent_emails: List[Dict[str, Any]] = []

    def clear_sent_emails(self) -> None:
        """Clears memory history of sent emails (used for test teardowns)."""
        self._sent_emails.clear()

    def get_last_sent_email(self) -> Optional[Dict[str, Any]]:
        """Returns the most recent email sent, or None if none sent."""
        return self._sent_emails[-1] if self._sent_emails else None

    @property
    def sent_emails(self) -> List[Dict[str, Any]]:
        return self._sent_emails

    def send_verification_email(
        self,
        to_email: str,
        token: str,
        tenant_name: str = "Ternline Security",
        base_url: Optional[str] = None,
    ) -> bool:
        """
        Sends an account activation and email verification link to a newly registered user.
        """
        frontend_base = (base_url or settings.FRONTEND_URL).rstrip("/")
        verification_link = f"{frontend_base}/verify-email?token={token}"

        subject = f"Verify your email for {tenant_name} | Ternline"
        
        text_body = (
            f"Welcome to Ternline.\n\n"
            f"Please verify your email address to activate your security operator account:\n\n"
            f"{verification_link}\n\n"
            f"This link will expire in {settings.EMAIL_VERIFICATION_EXPIRE_HOURS} hours.\n\n"
            f"If you did not register for this account, please disregard this email."
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 24px; }}
    .card {{ max-width: 540px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 32px; }}
    .badge {{ display: inline-block; background: #0284c7; color: #fff; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; padding: 4px 8px; border-radius: 4px; }}
    h1 {{ color: #ffffff; font-size: 20px; margin: 16px 0 8px 0; }}
    p {{ color: #9ca3af; font-size: 14px; line-height: 1.6; }}
    .btn {{ display: inline-block; background: #0284c7; color: #ffffff !important; text-decoration: none; font-weight: 600; font-size: 14px; padding: 12px 24px; border-radius: 6px; margin: 20px 0; }}
    .footer {{ font-size: 12px; color: #6b7280; border-top: 1px solid #1f2937; margin-top: 24px; padding-top: 16px; }}
    code {{ background: #1f2937; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Security Activation</span>
    <h1>Verify Your Ternline Account</h1>
    <p>Welcome to Ternline. An account was requested for <strong>{to_email}</strong> under workspace <strong>{tenant_name}</strong>.</p>
    <p>To finalize your operator credentials and enable secure telemetry ingestion, please verify your email address below:</p>
    <a href="{verification_link}" class="btn" target="_blank">Verify Email Address</a>
    <p>Or paste this URL into your browser:<br><code>{verification_link}</code></p>
    <div class="footer">
      This link expires in {settings.EMAIL_VERIFICATION_EXPIRE_HOURS} hours. If you did not create this account, no action is needed.
    </div>
  </div>
</body>
</html>"""

        return self._dispatch(
            to_email=to_email,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            metadata={"type": "email_verification", "token": token, "verification_link": verification_link},
        )

    def send_password_reset_email(
        self,
        to_email: str,
        token: str,
        base_url: Optional[str] = None,
    ) -> bool:
        """Sends a secure password reset link."""
        frontend_base = (base_url or settings.FRONTEND_URL).rstrip("/")
        reset_link = f"{frontend_base}/reset-password?token={token}"

        subject = "Reset your Ternline account password"
        text_body = (
            f"A password reset request was received for your Ternline account.\n\n"
            f"Reset your password using the link below:\n{reset_link}\n\n"
            f"This link expires in {settings.PASSWORD_RESET_EXPIRE_HOURS} hour(s).\n"
            f"If you did not request this, please secure your account immediately."
        )
        html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family: sans-serif; background: #0b0f19; color: #fff; padding: 24px;">
  <div style="max-width: 500px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; padding: 24px; border-radius: 8px;">
    <h2 style="margin-top: 0;">Password Reset Request</h2>
    <p style="color: #9ca3af;">Click the button below to choose a new password:</p>
    <a href="{reset_link}" style="background: #ef4444; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
    <p style="font-size: 12px; color: #6b7280; margin-top: 20px;">Link expires in {settings.PASSWORD_RESET_EXPIRE_HOURS} hour(s).</p>
  </div>
</body>
</html>"""

        return self._dispatch(
            to_email=to_email,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            metadata={"type": "password_reset", "token": token, "reset_link": reset_link},
        )

    def _dispatch(
        self,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        record = {
            "to_email": to_email,
            "subject": subject,
            "text_body": text_body,
            "html_body": html_body,
            "metadata": metadata or {},
        }
        self._sent_emails.append(record)

        # 1. AWS SES Delivery (Production on AWS)
        if settings.AWS_SES_SOURCE:
            try:
                import boto3
                ses_client = boto3.client("ses", region_name=settings.AWS_REGION)
                response = ses_client.send_email(
                    Source=settings.AWS_SES_SOURCE,
                    Destination={"ToAddresses": [to_email]},
                    Message={
                        "Subject": {"Data": subject, "Charset": "UTF-8"},
                        "Body": {
                            "Text": {"Data": text_body, "Charset": "UTF-8"},
                            "Html": {"Data": html_body, "Charset": "UTF-8"},
                        },
                    },
                )
                logger.info("Email successfully sent via AWS SES to %s: MessageId=%s", to_email, response.get("MessageId"))
                return True
            except Exception as e:
                logger.error("AWS SES dispatch failed for %s: %s", to_email, e)

        # 2. Standard SMTP Delivery
        if settings.SMTP_HOST:
            try:
                msg = email.message.EmailMessage()
                msg["Subject"] = subject
                msg["From"] = settings.SMTP_FROM_EMAIL
                msg["To"] = to_email
                msg.set_content(text_body)
                msg.add_alternative(html_body, subtype="html")

                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                    if settings.SMTP_TLS:
                        server.starttls()
                    if settings.SMTP_USER and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                    server.send_message(msg)

                logger.info("Email successfully dispatched via SMTP to %s", to_email)
                return True
            except Exception as e:
                logger.error("SMTP dispatch failed for %s: %s", to_email, e)

        # 3. Development / Mock fallback
        logger.info("[MOCK EMAIL DISPATCH] Sent to %s: Subject='%s'", to_email, subject)
        return True


email_service = EmailDeliveryService()

