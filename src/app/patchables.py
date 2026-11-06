"""Route app actions through vpn_manager when tests monkeypatch it."""


def patched(name: str, local):
    import vpn_manager as vm  # noqa: PLC0415

    remote = getattr(vm, name, None)
    if remote is not None and remote is not local:
        return remote
    return local
