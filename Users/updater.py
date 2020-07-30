from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from .views import clearOTP

def start():
    scheduler = BackgroundScheduler()
    scheduler.add_job(clearOTP, 'interval', minutes=1)
    scheduler.start()