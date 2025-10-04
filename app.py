app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "dev_secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "postgresql+psycopg2://exp_user:strongpass@localhost:5432/expenses")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
login_mgr = LoginManager(app)
login_mgr.login_view = "login"