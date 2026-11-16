"""ASGI entry point: reads configuration from the environment."""

from .config import Settings
from .main import create_app

app = create_app(Settings())
