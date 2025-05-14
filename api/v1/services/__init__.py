from api.v1.services.user import UserService
from api.v1.services.device import DevicesService
from api.v1.services.audit_log import AuditLogService
from api.v1.services.notification import Notification
from api.v1.services.totp import TOTPService
from api.v1.services.oauth2 import OAuth2Service

user_service = UserService()
devices_service = DevicesService()
audit_log_service = AuditLogService()
notification_service = Notification()
totp_service = TOTPService()
oauth2_service = OAuth2Service()
