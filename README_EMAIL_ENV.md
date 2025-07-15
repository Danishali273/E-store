# E-Store Email Verification Environment Setup

This guide explains how to configure your `.env` file for enabling email verification in the E-Store Flask application.

## 1. Copy the Example

Duplicate the provided `.env` file (or `.env.example` if available) and rename it to `.env` in your project root.

## 2. Email Configuration Variables

Set the following variables in your `.env` file to enable email sending for verification:

```
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USE_SSL=False
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

- **MAIL_SERVER**: The SMTP server address. For Gmail, use `smtp.gmail.com`.
- **MAIL_PORT**: The SMTP port. For Gmail with TLS, use `587`.
- **MAIL_USE_TLS**: Set to `True` to use TLS encryption.
- **MAIL_USE_SSL**: Set to `False` (do not use SSL if using TLS).
- **MAIL_USERNAME**: Your email address (the sender).
- **MAIL_PASSWORD**: The app password for your email account (see below).
- **MAIL_DEFAULT_SENDER**: The default sender email address (usually same as `MAIL_USERNAME`).

## 3. Gmail App Password Setup

If you use Gmail, you must create an App Password:

1. Go to your Google Account > Security.
2. Enable 2-Step Verification if not already enabled.
3. Under "Signing in to Google," select **App Passwords**.
4. Generate a new app password for "Mail" and "Other" (give it a name like "E-Store").
5. Copy the generated password and use it as `MAIL_PASSWORD` in your `.env` file.

**Never use your main Gmail password!**

## 4. Example `.env` Email Section

```
# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USE_SSL=False
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

## 5. Restart the App

After updating your `.env`, restart your Flask app to apply changes.

---

**Note:**
- Do not share your `.env` file or app password publicly.
- For other email providers, update the SMTP settings accordingly.

For more help, see the Flask-Mail documentation: https://pythonhosted.org/Flask-Mail/
