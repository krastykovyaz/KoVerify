"""Server-rendered pages."""
import os

import re

from flask import Blueprint, abort, current_app, render_template, send_file

from .api import CODE_ALPHABET, CODE_LENGTH

bp = Blueprint("pages", __name__)

_CODE_RE = re.compile(f"^[{CODE_ALPHABET}]{{{CODE_LENGTH}}}$")


def _bad_code():
    return render_template(
        "download_error.html",
        error=f"Неверный код сессии: он состоит из {CODE_LENGTH} символов",
    ), 404


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/session/<code>")
def verify_page(code):
    if not _CODE_RE.match(code):
        return _bad_code()
    return render_template("verify.html", code=code)


@bp.route("/result/<code>")
def result_page(code):
    if not _CODE_RE.match(code):
        return _bad_code()
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
