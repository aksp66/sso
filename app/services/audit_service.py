# Ce module est remplacé par AuditLog.log() dans app/models/audit_log.py
# Utilisation directe dans les routes :
#
#   from app.models.audit_log import AuditLog, EVENT_LOGIN_SUCCESS
#   AuditLog.log(event_type=EVENT_LOGIN_SUCCESS, ip_address=request.remote_addr, ...)
#   db.session.commit()
