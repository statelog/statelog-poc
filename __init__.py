import json
import secrets
from cryptography.fernet import Fernet

print("ADMIN_API_KEY=" + secrets.token_urlsafe(48))
print("METRICS_API_KEY=" + secrets.token_urlsafe(48))
print("POSTGRES_PASSWORD=" + secrets.token_urlsafe(32))
print("JWT_KEYRING_JSON=" + json.dumps({"v2": secrets.token_urlsafe(64)}))
print("SECRET_ENCRYPTION_KEY=" + Fernet.generate_key().decode())
print("IP_HASH_PEPPER=" + secrets.token_urlsafe(48))
print("WEBHOOK_SECRET_PEPPER=" + secrets.token_urlsafe(48))
