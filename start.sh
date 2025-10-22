#!/usr/bin/env bash
set -e
: "${DATABASE_URL:?DATABASE_URL is required}"
: "${SECRET_KEY:?SECRET_KEY is required}"
exec gunicorn --workers 2 --threads 8 --timeout 60 --bind 0.0.0.0:${PORT:-8080} app:application
