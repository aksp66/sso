import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app

# ── Palette commune (tons pierre chauds, cohérente avec le thème web) ──────
_BG        = "#0f0d0a"
_CARD_BG   = "#1a1612"
_CARD_BORDER = "#2d2820"
_TEXT      = "#fafaf9"
_SECONDARY = "#a8a29e"
_MUTED     = "#78716c"
_BTN_START = "#1D4ED8"
_BTN_END   = "#0369A1"
_GREEN     = "#22C55E"
_RED       = "#EF4444"


def _base_html(title: str, body_inner: str) -> str:
    """Enveloppe commune pour tous les emails Nexus."""
    return f"""<!doctype html>
<html lang="fr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{_BG};font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:{_BG};padding:40px 16px;">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;">

        <!-- En-tête logo -->
        <tr><td style="padding-bottom:24px;text-align:center;">
          <span style="font-family:'Segoe UI',Arial,sans-serif;font-size:22px;font-weight:800;
                       letter-spacing:-0.03em;color:{_TEXT};">Nexus</span>
          <span style="display:block;font-size:11px;font-weight:600;letter-spacing:0.12em;
                       text-transform:uppercase;color:#3B82F6;margin-top:2px;">SSO</span>
        </td></tr>

        <!-- Carte principale -->
        <tr><td style="background:{_CARD_BG};border:1px solid {_CARD_BORDER};
                       border-radius:16px;padding:36px 40px;">
          {body_inner}
        </td></tr>

        <!-- Pied de page -->
        <tr><td style="padding-top:24px;text-align:center;">
          <p style="font-size:11px;color:{_MUTED};margin:0;line-height:1.7;">
            Nexus &mdash; Authentification unique sécurisée &bull; Sanguéra, Togo<br>
            Cet e-mail a été envoyé automatiquement, ne pas répondre.
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _btn(link: str, label: str, color: str = _BTN_START) -> str:
    return (
        f'<table cellpadding="0" cellspacing="0" style="margin:28px 0;">'
        f'<tr><td style="background:linear-gradient(135deg,{_BTN_START},{_BTN_END});'
        f'border-radius:10px;">'
        f'<a href="{link}" style="display:inline-block;padding:13px 30px;'
        f'color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;'
        f'letter-spacing:0.01em;">{label}</a>'
        f'</td></tr></table>'
    )


def _send(to_email: str, subject: str, text_body: str, html_body: str) -> None:
    cfg = current_app.config
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = cfg["SMTP_FROM"]
    msg["To"]      = to_email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html",  "utf-8"))
    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"]) as smtp:
        smtp.ehlo()
        if cfg["SMTP_PORT"] == 587:
            smtp.starttls()
        if cfg.get("SMTP_USER"):
            smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASS"])
        smtp.sendmail(cfg["SMTP_FROM"], [to_email], msg.as_string())


# ── E-mails ─────────────────────────────────────────────────────────────────

def send_verification_email(to_email: str, username: str, verify_link: str) -> None:
    text_body = (
        f"Bonjour {username},\n\n"
        f"Bienvenue sur Nexus ! Confirmez votre adresse e-mail en cliquant sur ce lien "
        f"(valable 24 heures) :\n{verify_link}\n\n"
        f"Si vous n'êtes pas à l'origine de cette inscription, ignorez cet e-mail."
    )
    inner = f"""
      <p style="font-size:13px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;
                color:#3B82F6;margin:0 0 14px;">Confirmation de compte</p>
      <h1 style="font-size:22px;font-weight:800;color:{_TEXT};margin:0 0 12px;
                 letter-spacing:-0.02em;">Bienvenue, {username}&nbsp;!</h1>
      <p style="font-size:14px;color:{_SECONDARY};line-height:1.75;margin:0 0 4px;">
        Votre compte Nexus est presque prêt.<br>
        Cliquez sur le bouton ci-dessous pour confirmer votre adresse e-mail
        et activer votre compte.
      </p>
      <p style="font-size:12px;color:{_MUTED};margin:0;">
        Ce lien est valable <strong style="color:{_TEXT};">24 heures</strong>.
      </p>
      {_btn(verify_link, "Confirmer mon e-mail")}
      <hr style="border:none;border-top:1px solid {_CARD_BORDER};margin:4px 0 20px;">
      <p style="font-size:12px;color:{_MUTED};line-height:1.6;margin:0;">
        Si vous n'êtes pas à l'origine de cette inscription, ignorez simplement cet e-mail.
        Votre adresse ne sera pas utilisée.
      </p>"""
    html_body = _base_html("Confirmez votre adresse e-mail — Nexus", inner)
    _send(to_email, "Confirmez votre adresse e-mail — Nexus", text_body, html_body)


def send_password_reset_email(to_email: str, reset_link: str) -> None:
    text_body = (
        f"Vous avez demandé la réinitialisation de votre mot de passe.\n\n"
        f"Cliquez sur ce lien (valable 1 heure) :\n{reset_link}\n\n"
        f"Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail."
    )
    inner = f"""
      <p style="font-size:13px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;
                color:#3B82F6;margin:0 0 14px;">Sécurité du compte</p>
      <h1 style="font-size:22px;font-weight:800;color:{_TEXT};margin:0 0 12px;
                 letter-spacing:-0.02em;">Réinitialisation du mot de passe</h1>
      <p style="font-size:14px;color:{_SECONDARY};line-height:1.75;margin:0 0 4px;">
        Nous avons reçu une demande de réinitialisation de mot de passe pour votre compte Nexus.
      </p>
      <p style="font-size:12px;color:{_MUTED};margin:0;">
        Ce lien est valable <strong style="color:{_TEXT};">1 heure</strong>.
      </p>
      {_btn(reset_link, "Réinitialiser mon mot de passe")}
      <hr style="border:none;border-top:1px solid {_CARD_BORDER};margin:4px 0 20px;">
      <p style="font-size:12px;color:{_MUTED};line-height:1.6;margin:0;">
        Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.
        Votre mot de passe ne sera pas modifié.
      </p>"""
    html_body = _base_html("Réinitialisation du mot de passe — Nexus", inner)
    _send(to_email, "Réinitialisation de votre mot de passe — Nexus", text_body, html_body)


def send_client_credentials_email(
    to_email: str, client_name: str, client_id: str, client_secret: str | None
) -> None:
    secret_text = client_secret or "(client public — aucun secret, utilisez PKCE)"
    text_body = (
        f"Votre demande d'accès pour « {client_name} » a été approuvée.\n\n"
        f"client_id     : {client_id}\n"
        f"client_secret : {secret_text}\n\n"
        f"Conservez ces informations en lieu sûr."
    )
    secret_row = (
        f'<tr>'
        f'<td style="padding:8px 0;font-size:12px;color:{_MUTED};white-space:nowrap;">client_secret</td>'
        f'<td style="padding:8px 0;padding-left:16px;">'
        f'<code style="background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.15);'
        f'padding:3px 8px;border-radius:6px;font-size:12px;color:#38BDF8;">{client_secret}</code>'
        f'</td></tr>'
        if client_secret else
        f'<tr>'
        f'<td style="padding:8px 0;font-size:12px;color:{_MUTED};">Type</td>'
        f'<td style="padding:8px 0;padding-left:16px;font-size:13px;color:{_TEXT};">Client public (PKCE requis)</td>'
        f'</tr>'
    )
    docs_link = f"{current_app.config['SSO_ISSUER']}/docs/developers/demarrage-rapide"
    inner = f"""
      <p style="font-size:13px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;
                color:{_GREEN};margin:0 0 14px;">Accès approuvé</p>
      <h1 style="font-size:22px;font-weight:800;color:{_TEXT};margin:0 0 12px;
                 letter-spacing:-0.02em;">Votre application est prête&nbsp;!</h1>
      <p style="font-size:14px;color:{_SECONDARY};line-height:1.75;margin:0 0 20px;">
        La demande d'accès pour <strong style="color:{_TEXT};">{client_name}</strong>
        a été approuvée. Voici vos identifiants OAuth2&nbsp;:
      </p>
      <table cellpadding="0" cellspacing="0" width="100%"
             style="background:rgba(0,0,0,0.2);border:1px solid {_CARD_BORDER};
                    border-radius:10px;padding:16px 20px;margin-bottom:4px;">
        <tr>
          <td style="padding:8px 0;font-size:12px;color:{_MUTED};white-space:nowrap;">client_id</td>
          <td style="padding:8px 0;padding-left:16px;">
            <code style="background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.15);
                         padding:3px 8px;border-radius:6px;font-size:12px;color:#38BDF8;">{client_id}</code>
          </td>
        </tr>
        {secret_row}
      </table>
      {_btn(docs_link, "Voir la documentation d'intégration")}
      <hr style="border:none;border-top:1px solid {_CARD_BORDER};margin:4px 0 20px;">
      <p style="font-size:12px;color:{_MUTED};line-height:1.6;margin:0;">
        Conservez le <code style="color:#38BDF8;">client_secret</code> en lieu sûr
        — il ne vous sera plus jamais affiché.
      </p>"""
    html_body = _base_html(f"Accès Nexus approuvé — {client_name}", inner)
    _send(to_email, f"Accès Nexus approuvé — {client_name}", text_body, html_body)


def send_email_change_email(to_email: str, username: str, confirm_link: str) -> None:
    text_body = (
        f"Bonjour {username},\n\n"
        f"Vous avez demandé à changer votre adresse e-mail Nexus.\n"
        f"Cliquez sur ce lien pour confirmer la nouvelle adresse (valable 1 heure) :\n{confirm_link}\n\n"
        f"Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail."
    )
    inner = f"""
      <p style="font-size:13px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;
                color:#3B82F6;margin:0 0 14px;">Changement d'adresse e-mail</p>
      <h1 style="font-size:22px;font-weight:800;color:{_TEXT};margin:0 0 12px;
                 letter-spacing:-0.02em;">Confirmez votre nouvelle adresse</h1>
      <p style="font-size:14px;color:{_SECONDARY};line-height:1.75;margin:0 0 4px;">
        Bonjour <strong style="color:{_TEXT};">{username}</strong>,<br>
        Vous avez demandé à modifier l'adresse e-mail associée à votre compte Nexus.
        Cliquez sur le bouton ci-dessous pour confirmer cette nouvelle adresse.
      </p>
      <p style="font-size:12px;color:{_MUTED};margin:0;">
        Ce lien est valable <strong style="color:{_TEXT};">1 heure</strong>.
      </p>
      {_btn(confirm_link, "Confirmer la nouvelle adresse")}
      <hr style="border:none;border-top:1px solid {_CARD_BORDER};margin:4px 0 20px;">
      <p style="font-size:12px;color:{_MUTED};line-height:1.6;margin:0;">
        Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.
        Votre adresse actuelle reste inchangée.
      </p>"""
    html_body = _base_html("Confirmez votre nouvelle adresse e-mail — Nexus", inner)
    _send(to_email, "Confirmez votre nouvelle adresse e-mail — Nexus", text_body, html_body)


def send_client_request_rejected_email(
    to_email: str, client_name: str, reason: str | None
) -> None:
    reason_text = reason or "Aucun motif détaillé n'a été fourni."
    text_body = (
        f"Votre demande d'accès pour « {client_name} » n'a pas été approuvée.\n\n"
        f"Motif : {reason_text}\n\n"
        f"Vous pouvez soumettre une nouvelle demande après correction."
    )
    inner = f"""
      <p style="font-size:13px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;
                color:{_RED};margin:0 0 14px;">Demande non approuvée</p>
      <h1 style="font-size:22px;font-weight:800;color:{_TEXT};margin:0 0 12px;
                 letter-spacing:-0.02em;">Demande d'accès refusée</h1>
      <p style="font-size:14px;color:{_SECONDARY};line-height:1.75;margin:0 0 20px;">
        La demande pour <strong style="color:{_TEXT};">{client_name}</strong>
        n'a pas pu être approuvée pour la raison suivante&nbsp;:
      </p>
      <div style="background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);
                  border-radius:10px;padding:14px 18px;margin-bottom:24px;">
        <p style="font-size:13px;color:#FCA5A5;margin:0;line-height:1.6;">{reason_text}</p>
      </div>
      <hr style="border:none;border-top:1px solid {_CARD_BORDER};margin:0 0 20px;">
      <p style="font-size:12px;color:{_MUTED};line-height:1.6;margin:0;">
        Vous pouvez soumettre une nouvelle demande après avoir corrigé les points mentionnés.
      </p>"""
    html_body = _base_html(f"Demande d'accès non approuvée — {client_name}", inner)
    _send(to_email, f"Demande d'accès Nexus non approuvée — {client_name}", text_body, html_body)
