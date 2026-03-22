import jwt
import logging
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

logger = logging.getLogger(__name__)


class SupabaseUser:
    """Lightweight user object populated from Supabase JWT claims."""

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
    """Validate Supabase-issued JWTs on every request."""

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ', 1)[1].strip()
        if not token:
            return None

        try:
            payload = jwt.decode(
                token,
                settings.SUPABASE_JWT_SECRET,
                algorithms=['HS256'],
                options={'verify_aud': False},
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired.')
        except jwt.InvalidTokenError as exc:
            raise AuthenticationFailed(f'Invalid token: {exc}')

        user = SupabaseUser(payload)
        return (user, token)

    def authenticate_header(self, request):
        return 'Bearer realm="fuzzi"'
