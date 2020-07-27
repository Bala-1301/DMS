from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import Users.routing
from DMS_1.knoxTokenAuthentication import TokenAuthMiddlewareStack

application = ProtocolTypeRouter({
    # Empty for now (http->django views is added by default)
		'websocket' : TokenAuthMiddlewareStack(
			URLRouter(
				Users.routing.websocket_urlpatterns
			)
		),
})