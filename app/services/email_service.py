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


def _send(to_email: str, subject: str, text_body: str, html_body: str) -> None:
    cfg = current_app.config
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"]) as smtp:
        smtp.ehlo()
        if cfg["SMTP_PORT"] == 587:
            smtp.starttls()
        if cfg.get("SMTP_USER"):
            smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASS"])
        smtp.sendmail(cfg["SMTP_FROM"], [to_email], msg.as_string())


def send_client_credentials_email(
    to_email: str, client_name: str, client_id: str, client_secret: str | None
) -> None:
    """Envoie les identifiants OAuth2 après approbation d'une demande d'accès."""
    secret_text = client_secret or "(client public — aucun secret, utilisez PKCE)"
    text_body = (
        f"Votre demande d'accès pour l'application « {client_name} » a été approuvée.\n\n"
        f"client_id : {client_id}\n"
        f"client_secret : {secret_text}\n\n"
        f"Conservez ces informations en lieu sûr. Documentation : "
        f"{current_app.config['SSO_ISSUER']}/docs/developers/demarrage-rapide"
    )
    secret_row = (
        f'<tr><td style="padding:6px 0;color:#94A3B8;">client_secret</td>'
        f'<td style="padding:6px 0;"><code style="background:rgba(255,255,255,0.08);'
        f'padding:3px 8px;border-radius:6px;color:#38BDF8;">{client_secret}</code></td></tr>'
        if client_secret else
        '<tr><td style="padding:6px 0;color:#94A3B8;">Type</td>'
        '<td style="padding:6px 0;color:#F0F6FF;">Client public (PKCE requis)</td></tr>'
    )
    html_body = f"""
<!doctype html>
<html lang="fr">
<body style="margin:0;padding:0;background:#030d1c;font-family:'Segoe UI',sans-serif;">
  <div style="max-width:520px;margin:40px auto;padding:32px;
              background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.10);
              border-radius:16px;color:#F0F6FF;">
    <h2 style="font-size:20px;font-weight:700;margin:0 0 16px;color:#60A5FA;">
      Demande d'accès approuvée
    </h2>
    <p style="font-size:14px;color:#94A3B8;line-height:1.7;margin:0 0 20px;">
      Votre application <strong style="color:#F0F6FF;">{client_name}</strong> peut maintenant
      utiliser Nexus pour authentifier ses utilisateurs.
    </p>
    <table style="width:100%;font-size:13px;border-collapse:collapse;margin-bottom:20px;">
      <tr><td style="padding:6px 0;color:#94A3B8;">client_id</td>
          <td style="padding:6px 0;"><code style="background:rgba(255,255,255,0.08);
              padding:3px 8px;border-radius:6px;color:#38BDF8;">{client_id}</code></td></tr>
      {secret_row}
    </table>
    <a href="{current_app.config['SSO_ISSUER']}/docs/developers/demarrage-rapide"
       style="display:inline-block;padding:12px 28px;background:linear-gradient(135deg,#1D4ED8,#0369A1);
              color:#fff;font-weight:600;font-size:14px;text-decoration:none;border-radius:10px;">
      Voir la documentation d'intégration
    </a>
    <p style="font-size:12px;color:#64748B;margin-top:24px;line-height:1.6;">
      Conservez le client_secret en lieu sûr — il ne sera plus jamais affiché.
    </p>
  </div>
</body>
</html>"""
    _send(to_email, f"Accès Nexus approuvé — {client_name}", text_body, html_body)


def send_client_request_rejected_email(to_email: str, client_name: str, reason: str | None) -> None:
    """Notifie le demandeur que sa demande d'accès a été refusée."""
    reason_text = reason or "Aucun motif détaillé n'a été fourni."
    text_body = (
        f"Votre demande d'accès pour l'application « {client_name} » n'a pas été approuvée.\n\n"
        f"Motif : {reason_text}\n\n"
        f"Vous pouvez soumettre une nouvelle demande après correction."
    )
    html_body = f"""
<!doctype html>
<html lang="fr">
<body style="margin:0;padding:0;background:#030d1c;font-family:'Segoe UI',sans-serif;">
  <div style="max-width:480px;margin:40px auto;padding:32px;
              background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.10);
              border-radius:16px;color:#F0F6FF;">
    <h2 style="font-size:20px;font-weight:700;margin:0 0 16px;color:#F87171;">
      Demande d'accès non approuvée
    </h2>
    <p style="font-size:14px;color:#94A3B8;line-height:1.7;margin:0 0 16px;">
      Votre demande pour l'application <strong style="color:#F0F6FF;">{client_name}</strong>
      n'a pas été approuvée.
    </p>
    <p style="font-size:13px;color:#F0F6FF;background:rgba(239,68,68,0.1);
              border:1px solid rgba(239,68,68,0.2);border-radius:10px;padding:12px 16px;">
      {reason_text}
    </p>
    <p style="font-size:12px;color:#64748B;margin-top:20px;line-height:1.6;">
      Vous pouvez soumettre une nouvelle demande après avoir corrigé les points mentionnés.
    </p>
  </div>
</body>
</html>"""
    _send(to_email, f"Demande d'accès Nexus non approuvée — {client_name}", text_body, html_body)
