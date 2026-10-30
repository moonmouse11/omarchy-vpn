"""Lookup helpers shared by tools and servers."""

from app.registry import visible_providers


def provider_named(name: str):
    return next((p for p in visible_providers() if p.name == name), None)
