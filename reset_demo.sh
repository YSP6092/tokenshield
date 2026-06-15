#!/bin/bash
docker exec flask-server python -c "
from app import create_app
from app.extensions import db
from app.models import User, Session
app = create_app()
with app.app_context():
    demo = User.query.filter_by(username='demo').first()
    demo.is_admin = False
    demo.failed_login_attempts = 0
    demo.requires_2fa = False
    demo.totp_enabled = False
    # Revoke all old sessions so fresh login works
    Session.query.filter_by(user_id=demo.id).update({'is_active': False})
    db.session.commit()
    print('demo account reset and ready')
"
