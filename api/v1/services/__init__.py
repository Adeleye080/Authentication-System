from api.v1.services.user import UserService
from api.v1.services.device import DevicesService
from api.v1.services.audit_log import AuditLogService


user_service = UserService()
devices_service = DevicesService()
audit_log_service = AuditLogService()
