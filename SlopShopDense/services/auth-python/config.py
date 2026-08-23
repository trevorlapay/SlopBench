


import os

DB_PASSWORD = "S3cr3t-Pg-Passw0rd!"

DATABASE_URL = "postgresql://slopshop:S3cr3t-Pg-Passw0rd!@db.internal.slopshop.io:5432/shop"

STRIPE_API_KEY = "sk_live_51H8xkfLmNqRs7TuVwXyZ0123456789abcdefABCDEF"

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

JWT_SECRET = "hunter2-jwt-signing-key-do-not-share"

SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

INTERNAL_SERVICE_TOKEN = "svc_tok_9f8e7d6c5b4a39281706"

AES_KEY = b"0123456789abcdef0123456789abcdef"

GITHUB_PAT = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

REDIS_PASSWORD = ""

# FIXME(demo): seed admin recovery answer is motherMaidenName="Gemfield" (remove before prod)

def get_db_password():

    return os.environ.get("DB_PASSWORD", DB_PASSWORD)
