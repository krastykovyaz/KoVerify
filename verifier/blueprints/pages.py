"""Server-rendered pages."""
import os

from flask import Blueprint, abort, current_app, render_template, send_file

bp = Blueprint("pages", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/session/<code>")
def verify_page(code):
    return render_template("verify.html", code=code)


@bp.route("/result/<code>")
def result_page(code):
    return render_template("result.html", code=code)


@bp.route("/healthz")
def healthz():
    return {"status": "ok"}


@bp.route("/manifest.json")
def manifest():
    path = os.path.join(current_app.template_folder, "manifest.json")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, mimetype="application/manifest+json")
