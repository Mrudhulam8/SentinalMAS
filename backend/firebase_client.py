import os

import firebase_admin
from firebase_admin import credentials, firestore

from backend.config import settings

_client = None
_unavailable = False


class FirestoreUnavailable(RuntimeError):
    """Firestore is not configured / cannot be reached in this environment."""


def get_firestore():
    """Return a cached Firestore client, or raise FirestoreUnavailable fast.

    Firestore is optional: the pipeline runs fully offline against local seed
    data. To keep that path fast we (a) skip Firestore entirely when no
    credentials are configured, and (b) remember a failed connection so we
    never re-run the (slow, blocking) credential probe on every call.
    """
    global _client, _unavailable

    if _unavailable:
        raise FirestoreUnavailable("Firestore unavailable (cached)")
    if _client is not None:
        return _client

    has_service_account = os.path.exists(settings.firebase_service_account_path)
    if not has_service_account and not settings.firebase_project_id:
        _unavailable = True
        raise FirestoreUnavailable("No Firebase credentials configured")

    try:
        if not firebase_admin._apps:
            cred = (
                credentials.Certificate(settings.firebase_service_account_path)
                if has_service_account
                else credentials.ApplicationDefault()
            )
            firebase_admin.initialize_app(
                cred,
                {"projectId": settings.firebase_project_id} if settings.firebase_project_id else None,
            )
        _client = firestore.client()
        return _client
    except Exception as exc:
        _unavailable = True
        raise FirestoreUnavailable(str(exc)) from exc
