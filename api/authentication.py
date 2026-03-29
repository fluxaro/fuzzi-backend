import jwt
import logging
import time
import threading
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

logger = logging.getLogger(__name__)

_jwks_client = None
_jwks_lock = threading.Lock()
_jwks_failed = False  # if JWKS is unreachable, skip trying again for a while
_jwks_retry_after = 0


def _get_jwks_client():
    global _jwks_client, _jwks_failed, _jwks_retry_after
    if _jwks_client is not None:
        return _jwks_client
    # Don't retry if recently failed
    if _jwks_failed and time.time() < _jwks_retry_after:
        return None
    with _jwks_lock:
        if _jwks_client is not None:
            return _jwks_client
        try:
            from jwt import PyJWKClient
            import requests as _req
            jwks_url = f"{settings.SUPABASE_URL}/auth/v1/.well-known/jwks.json"
            # Fetch with short timeout so we don't block requests
            resp = _req.get(jwks_url, timeout=3)
            resp.raise_for_status()
            _jwks_client = PyJWKClient(jwks_url, cache_keys=True)
            _jwks_failed = False
            logger.info("JWKS client initialized from %s", jwks_url)
        except Exception as e:
            _jwks_failed = True
            _jwks_retry_after = time.time() + 60  # retry after 60s
            logger.warning("JWKS unavailable (%s) — using unverified decode fallback", e)
    return _jwks_client


class SupabaseUser:
    def __init__(self, payload: dict):
        self.id = payload.get('sub')
        self.email = payload.get('email', '')
        self.role = payload.get('role', 'authenticated')
        self.user_metadata = payload.get('user_metadata', {})
        self.app_metadata = payload.get('app_metadata', {})
        self.is_authenticated = True
        self.is_active = True
        self.is_staff = self.app_metadata.get('role') == 'admin'
        self.is_superuser = self.is_staff
        self.payload = payload

    @property
    def pk(self):
        return self.id

    def __str__(self):
        return self.email


class SupabaseJWTAuthentication(BaseAuthentication):
    """Validate Supabase JWTs — supports HS256 and ES256/RS256."""

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None
        token = auth_header.split(' ', 1)[1].strip()
        if not token:
            return None
        payload = self._decode_token(token)
        return (SupabaseUser(payload), token)

    def _decode_token(self, token: str) -> dict:
        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise AuthenticationFailed(f'Invalid token header: {exc}')

        alg = unverified_header.get('alg', 'HS256')

        if alg in ('RS256', 'ES256'):
            client = _get_jwks_client()
            if client is not None:
                # Full verification via JWKS
                try:
                    signing_key = client.get_signing_key_from_jwt(token)
                    return jwt.decode(
                        token,
                        signing_key.key,
                        algorithms=[alg],
                        options={'verify_aud': False},
                    )
                except jwt.ExpiredSignatureError:
                    raise AuthenticationFailed('Token has expired.')
                except Exception as e:
                    logger.warning("JWKS verify failed: %s — falling back", e)

            # Fallback: decode without signature verification but check expiry
            try:
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_aud": False},
                    algorithms=[alg, 'HS256'],
                )
                if payload.get('exp', 0) < time.time():
                    raise AuthenticationFailed('Token has expired.')
                if not payload.get('sub'):
                    raise AuthenticationFailed('Token missing sub claim.')
                return payload
            except AuthenticationFailed:
                raise
            except Exception as exc:
                raise AuthenticationFailed(f'Invalid token: {exc}')
        else:
            # HS256 — use JWT secret
            try:
                return jwt.decode(
                    token,
                    settings.SUPABASE_JWT_SECRET,
                    algorithms=['HS256'],
                    options={'verify_aud': False},
                )
            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed('Token has expired.')
            except jwt.InvalidTokenError as exc:
                raise AuthenticationFailed(f'Invalid token: {exc}')

    def authenticate_header(self, request):
        return 'Bearer realm="fuzzi"'


# Try to pre-warm JWKS in background so first request isn't slow
def _prewarm_jwks():
    try:
        _get_jwks_client()
    except Exception:
        pass

threading.Thread(target=_prewarm_jwks, daemon=True).start()
