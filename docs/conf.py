# Sphinx configuration for uniconn.

import sys
from pathlib import Path

# Add src to path so autodoc can find the module
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

project = "uniconn"
copyright = "2026, uniconn contributors"
author = "uniconn contributors"
release = "0.2.0"

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
html_static_path = ["_static"]

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "special-members": "__init__, __aenter__, __aexit__",
}
autodoc_typehints = "description"

# Intersphinx
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
    "asyncssh": ("https://asyncssh.readthedocs.io/en/latest/", None),
}

# Napoleon settings (Google/Numpy docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
