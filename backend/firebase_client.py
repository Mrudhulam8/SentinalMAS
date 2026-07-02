import os

import firebase_admin
from firebase_admin import credentials, firestore

from backend.config import settings

_app = None


def get_firestore():
    global _app
    if _app is None:
        if os.path.exists(settings.firebase_service_account_path):
            cred = credentials.Certificate(settings.firebase_service_account_path)
        else:
            cred = credentials.ApplicationDefault()
        _app = firebase_admin.initialize_app(
            cred, {"projectId": settings.firebase_project_id} if settings.firebase_project_id else None
        )
    return firestore.client()
