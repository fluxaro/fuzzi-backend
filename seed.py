"""
Seed script — run with: python seed.py
Creates Supabase storage buckets and optionally a demo admin user.
"""
import os
import sys
import django

sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fuzzi_backend.settings")
django.setup()

from django.conf import settings
from api.supabase_client import get_service_client

BUCKETS = [
    settings.SUPABASE_REPORTS_BUCKET,
    settings.SUPABASE_SCREENSHOTS_BUCKET,
    settings.SUPABASE_ARTIFACTS_BUCKET,
]


def create_buckets():
    client = get_service_client()
    for bucket in BUCKETS:
        try:
            client.storage.create_bucket(bucket, options={"public": False})
            print(f"  ✓ Bucket created: {bucket}")
        except Exception as e:
            if "already exists" in str(e).lower() or "Duplicate" in str(e):
                print(f"  ~ Bucket already exists: {bucket}")
            else:
                print(f"  ✗ Failed to create bucket {bucket}: {e}")


def create_demo_user():
    client = get_service_client()
    try:
        res = client.auth.admin.create_user({
            "email": "admin@fuzzi.dev",
            "password": "Fuzzi@Admin2024!",
            "email_confirm": True,
            "user_metadata": {"full_name": "Fuzzi Admin"},
            "app_metadata": {"role": "admin"},
        })
        from api.models import UserProfile
        UserProfile.objects.get_or_create(
            supabase_uid=res.user.id,
            defaults={
                "email": "admin@fuzzi.dev",
                "full_name": "Fuzzi Admin",
                "role": "admin",
            },
        )
        print("  ✓ Demo admin user created: admin@fuzzi.dev / Fuzzi@Admin2024!")
    except Exception as e:
        if "already" in str(e).lower():
            print("  ~ Demo user already exists")
        else:
            print(f"  ✗ Failed to create demo user: {e}")


if __name__ == "__main__":
    print("\n=== Fuzzi Seed Script ===\n")
    print("Creating storage buckets...")
    create_buckets()
    print("\nCreating demo admin user...")
    create_demo_user()
    print("\n✅ Seed complete.\n")
