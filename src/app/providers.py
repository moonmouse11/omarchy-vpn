"""Lookup helpers shared by tools and servers."""

from app.registry import _provider_pool


def provider_named(name: str):
    """Every registered provider — including ones hidden from the server list."""
    return next((p for p in _provider_pool() if p.name == name), None)
