from flask import Blueprint

# We keep templates in ../templates so Flask finds them
ioc_bp = Blueprint("ioc", __name__, template_folder="../templates")

# Import routes last to avoid circular import
from . import routes  # noqa: E402,F401
