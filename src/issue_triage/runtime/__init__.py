"""Explicit local execution boundaries; importing this package starts nothing."""

from .env import child_environment

__all__ = ["child_environment"]
