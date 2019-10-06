from app import app, db
from app.models import User, Scheme, Notification, Message


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Scheme': Scheme, 'Message': Message,
            'Notification': Notification}