import logging
from django.conf import settings
from supabase import create_client, Client

logger = logging.getLogger(__name__)

_client: Client | None = None
_service_client: Client | None = None


def get_supabase_client() -> Client:
    """Anon-key client (respects RLS)."""
    global _client
    if _client is None:
        _client = create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)
    return _client


def get_service_client() -> Client:
    """Service-role client (bypasses RLS — use carefully)."""
    global _service_client
    if _service_client is None:
        _service_client = create_client(
            settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY
        )
    return _service_client


def get_signed_url(bucket: str, path: str, expires_in: int = 3600) -> str | None:
    """Return a signed URL for a private bucket object."""
    try:
        client = get_service_client()
        res = client.storage.from_(bucket).create_signed_url(path, expires_in)
        return res.get('signedURL') or res.get('signedUrl')
    except Exception as exc:
        logger.error('Failed to create signed URL for %s/%s: %s', bucket, path, exc)
        return None


def upload_file(bucket: str, path: str, data: bytes, content_type: str = 'application/octet-stream') -> bool:
    """Upload bytes to a Supabase storage bucket."""
    try:
        client = get_service_client()
        client.storage.from_(bucket).upload(path, data, {'content-type': content_type, 'upsert': 'true'})
        return True
    except Exception as exc:
        logger.error('Upload failed for %s/%s: %s', bucket, path, exc)
        return False
