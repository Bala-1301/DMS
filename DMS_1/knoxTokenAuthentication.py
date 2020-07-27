from channels.auth import AuthMiddlewareStack
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import AnonymousUser
from django.db import close_old_connections
from knox.auth import TokenAuthentication

class TokenAuthMiddleware:
	"""
	Token authorization middleware for Django Channels 2
	"""

	def __init__(self, inner):
			self.inner = inner

	def __call__(self, scope):
		headers = dict(scope['headers'])
		if b'authorization' in headers:
				try:
					knoxAuth = TokenAuthentication()
					user, auth_token = knoxAuth.authenticate_credentials(tokenString.encode(HTTP_HEADER_ENCODING))
					if token_name == 'Token':
						token = Token.objects.get(key=token_key)
						scope['user'] = user
						close_old_connections()
				except auth_token.DoesNotExist:
					scope['user'] = AnonymousUser()
		return self.inner(scope)

TokenAuthMiddlewareStack = lambda inner: TokenAuthMiddleware(AuthMiddlewareStack(inner))



