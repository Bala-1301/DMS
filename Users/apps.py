from django.apps import AppConfig

class UsersConfig(AppConfig):
    name = 'Users'
    
    def ready(self):
        from Users import updater
        updater.start()