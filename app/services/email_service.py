import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app


def send_password_reset_email(to_email: str, reset_link: str) -> None:
    cfg = current_app.config
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Réinitialisation de votre mot de passe — SSO"
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = to_email

    text_body = (
        f"Vous avez demandé la réinitialisation de votre mot de passe.\n\n"
        f"Cliquez sur le lien suivant (valable 1 heure) :\n{reset_link}\n\n"
        f"Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail."
    )
    html_body = f"""
<!doctype html>
<html lang="fr">
<body style="margin:0;padding:0;background:#030d1c;font-family:'Segoe UI',sans-serif;">
  <div style="max-width:480px;margin:40px auto;padding:32px;
              background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.10);
              border-radius:16px;color:#F0F6FF;">
    <h2 style="font-size:20px;font-weight:700;margin:0 0 16px;color:#60A5FA;">
      Réinitialisation du mot de passe
    </h2>
    <p style="font-size:14px;color:#94A3B8;line-height:1.7;margin:0 0 24px;">
      Vous avez demandé la réinitialisation de votre mot de passe.<br>
      Ce lien est valable <strong style="color:#F0F6FF;">1 heure</strong>.
    </p>
    <a href="{reset_link}"
       style="display:inline-block;padding:12px 28px;background:linear-gradient(135deg,#1D4ED8,#0369A1);
              color:#fff;font-weight:600;font-size:14px;text-decoration:none;border-radius:10px;">
      Réinitialiser mon mot de passe
    </a>
    <p style="font-size:12px;color:#64748B;margin-top:24px;line-height:1.6;">
      Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.<br>
      Votre mot de passe ne sera pas modifié.
    </p>
  </div>
</body>
</html>"""

    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"]) as smtp:
        smtp.ehlo()
        if cfg["SMTP_PORT"] == 587:
            smtp.starttls()
        if cfg.get("SMTP_USER"):
            smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASS"])
        smtp.sendmail(cfg["SMTP_FROM"], [to_email], msg.as_string())
