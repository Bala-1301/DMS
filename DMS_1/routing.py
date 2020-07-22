from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import Users.routing

application = ProtocolTypeRouter({
    # Empty for now (http->django views is added by default)
		'websocket' : AuthMiddlewareStack(
			URLRouter(
				Users.routing.websocket_urlpatterns
			)
		),
})