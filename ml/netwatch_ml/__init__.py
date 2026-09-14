"""Offline tooling for netwatch Diagnose models.

Features are computed by netwatch itself (`netwatch diagnose features`); this
package only reads them. See load.py.
"""

from .load import Dataset, SchemaMismatch, load

__all__ = ["Dataset", "SchemaMismatch", "load"]
