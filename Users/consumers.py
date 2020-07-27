from rest_framework.permissions import IsAuthenticated
from channels.consumer import AsyncConsumer
from knox.auth import TokenAuthentication

class DoctorPatientConsumer(AsyncConsumer):
	
	async def websocket_connect(self, event):
		self.doc = self.scope['url_route']['kwargs']['doctor_id']
		print(self.scope['user'])
		if(self.scope['user'] != "AnonymousUser"):
			await self.send({
					"type": "websocket.accept",
			})

	async def websocket_receive(self, event):
		return

	async def websocket_disconnect(self, event):
		print(event)
		