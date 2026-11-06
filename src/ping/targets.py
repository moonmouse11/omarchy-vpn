"""Happ server endpoints for direct TCP ping (legacy path; Happ uses delayping)."""

from happ.servers import all_servers, server_params


def happ_ping_targets() -> list[tuple[str, str, int]]:

    targets = []
    for server in all_servers():
        params = server_params(server["name"])
        if params:
            targets.append((server["name"], params["host"], params["port"]))
    return targets
