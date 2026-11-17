"""ASGI entry point: reads configuration from the environment."""

from .config import Settings
from .main import create_app

import os

# Existing deployments remain unchanged unless explicitly configured. Loading
# private files can fail startup; never fall back to an unsigned/weak runtime.
if os.environ.get("KG_NATIVE_MDM_CONFIG"):
    from .native_mdm_config import factory
    engine, runtime, _ = factory()
    app = create_app(Settings(), engine=engine, native_mdm_runtime=runtime)
else:
    app = create_app(Settings())
