from importlib.machinery import SourceFileLoader
from pathlib import Path


BASE_DIR = Path(__file__).parent
backend_path = BASE_DIR / "Template-backend.py"

module = SourceFileLoader("template_backend", str(backend_path)).load_module()
app = module.app
