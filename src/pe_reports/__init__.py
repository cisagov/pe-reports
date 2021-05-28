"""The example library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.
from ._version import __version__  # noqa: F401
<<<<<<< HEAD
from .example import example_div

__all__ = ["example_div"]
=======
from .report_generator import main
>>>>>>> 941169fb38926b928e08597e53869cc45b0ba796
