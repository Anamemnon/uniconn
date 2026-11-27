# Sphinx configuration for uniconn.

import os
import sys
from pathlib import Path

# Add src to path so autodoc can find the module
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from uniconn import __version__

project = "uniconn"
copyright = "2026, uniconn contributors"
author = "uniconn contributors"
version = __version__
release = __version__

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.autosectionlabel",
    "sphinx_rtd_theme",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_static_path: list[str] = []
autosectionlabel_prefix_document = True

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "special-members": "__init__, __aenter__, __aexit__",
}
autodoc_typehints = "description"

# Intersphinx (set UNICONN_DOCS_OFFLINE=1 for strict offline -W builds)
if os.environ.get("UNICONN_DOCS_OFFLINE", "").strip().lower() in ("1", "true", "yes"):
    intersphinx_mapping: dict[str, tuple[str, str | None]] = {}
else:
    intersphinx_mapping = {
        "python": ("https://docs.python.org/3", None),
        "pydantic": ("https://docs.pydantic.dev/latest/", None),
        "asyncssh": ("https://asyncssh.readthedocs.io/en/latest/", None),
    }

# Napoleon settings (Google/Numpy docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
