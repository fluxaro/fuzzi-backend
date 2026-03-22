#!/bin/bash
set -e

echo "=== Installing dependencies ==="
pip install -r requirements.txt

echo "=== Collecting static files ==="
python manage.py collectstatic --noinput --clear

echo "=== Running migrations ==="
python manage.py migrate --noreload 2>&1 || echo "WARNING: Migration skipped — set DB_PASSWORD in Vercel env vars"

echo "=== Build complete ==="
