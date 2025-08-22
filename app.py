from flask import Flask
from dotenv import load_dotenv
import datetime
from ioc import ioc_bp


load_dotenv()

def create_app():
    app = Flask(__name__)
    # SECRET_KEY is read by Flask from environment automatically; you can also set:
    # app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "devkey")

    # Add a tiny context processor for the footer year
    @app.context_processor
    def inject_year():
        return {"current_year": datetime.datetime.now().year}

    app.register_blueprint(ioc_bp)
    return app

# For `flask run`, Flask will import app.py and look for `app` or `create_app`.
app = create_app()
