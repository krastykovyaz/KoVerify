"""Production entry point: gunicorn wsgi:app"""
from verifier import create_app

app = create_app()
