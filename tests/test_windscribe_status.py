from providers.vendor.windscribe_status import parse_status


def test_2217_logged_out_status_is_recognized():
    state = parse_status(
        "Internet connectivity: available\nLogin state: Logged out\nFirewall state: Off\n"
    )

    assert state.recognized is True
    assert state.internet == "available"
    assert state.login_state == "logged_out"
    assert state.connection_state == "unknown"
    assert state.firewall == "off"


def test_2217_disconnected_status_is_normalized():
    state = parse_status(
        "Internet connectivity: available\n"
        "Login state: Logged in\n"
        "Firewall state: Always On\n"
        "Connect state: Disconnected\n"
        "Public IP: 198.51.100.8\n"
        "Data usage: 0 bytes / 2.00 GB\n"
        "Update available: 2.25.8\n"
    )

    assert state.recognized is True
    assert state.login_state == "logged_in"
    assert state.connection_state == "disconnected"
    assert state.firewall == "always_on"
    assert state.ip_address == "198.51.100.8"
    assert state.ip_is_vpn is False
    assert state.data_usage == "0 bytes / 2.00 GB"
    assert state.update_version == "2.25.8"


def test_2217_connected_status_splits_protocol_and_port():
    state = parse_status(
        "Internet connectivity: available\n"
        "Login state: Logged in\n"
        "Firewall state: On\n"
        "Connect state: Connected\n"
        "Location: US East - New York - Empire\n"
        "Protocol: Stealth:443\n"
        "VPN IP: 203.0.113.4\n"
        "Data usage: 100.0 MB / 10.00 GB\n"
    )

    assert state.recognized is True
    assert state.connection_state == "connected"
    assert state.location == "US East - New York - Empire"
    assert state.protocol == "stealth"
    assert state.port == "443"
    assert state.ip_address == "203.0.113.4"
    assert state.ip_is_vpn is True


def test_2258_connected_status_is_normalized():
    state = parse_status(
        "Login: Logged in\n"
        "Connection: Connected to New York (checking the connection)\n"
        "Protocol: WireGuard:443\n"
        "IP: 203.0.113.8 (VPN)\n"
        "Firewall: On\n"
        "Data usage: 0 bytes / 0 bytes\n"
        "Internet: Available\n"
        "Update: 2.26.0 available\n"
    )

    assert state.recognized is True
    assert state.login_state == "logged_in"
    assert state.connection_state == "connected"
    assert state.location == "New York"
    assert state.checking is True
    assert state.network_interference is False
    assert state.protocol == "wireguard"
    assert state.port == "443"
    assert state.ip_address == "203.0.113.8"
    assert state.ip_is_vpn is True
    assert state.firewall == "on"
    assert state.data_usage == "0 bytes / 0 bytes"
    assert state.internet == "available"
    assert state.update_version == "2.26.0"


def test_2258_network_interference_and_public_ip_are_normalized():
    state = parse_status(
        "Login: Logged in\n"
        "Connection: Connected to Toronto (network interference detected)\n"
        "IP: 198.51.100.9 (public)\n"
        "Firewall: Always On\n"
        "Internet: Unavailable\n"
    )

    assert state.connection_state == "connected"
    assert state.location == "Toronto"
    assert state.checking is False
    assert state.network_interference is True
    assert state.ip_address == "198.51.100.9"
    assert state.ip_is_vpn is False
    assert state.firewall == "always_on"
    assert state.internet == "unavailable"


def test_2258_connection_annotations_are_removed_case_insensitively():
    state = parse_status(
        "Login: Logged in\nConnection: Connected to New York (Network Interference Detected)\n"
    )

    assert state.location == "New York"
    assert state.network_interference is True


def test_2258_error_states_keep_the_reason():
    state = parse_status(
        "Login: Error: Need 2FA code\n"
        "Connection: Error: Session expired\n"
        "Firewall: Off\n"
        "Internet: Available\n"
    )

    assert state.recognized is True
    assert state.login_state == "error"
    assert state.login_error == "Need 2FA code"
    assert state.connection_state == "error"


def test_known_labels_with_unsupported_values_are_not_recognized():
    state = parse_status("Login: Logged in\nConnection: Established to New York\n")

    assert state.recognized is False
    assert state.login_state == "logged_in"
    assert state.connection_state == "unknown"


def test_2258_unrelated_output_is_not_recognized():
    state = parse_status("Windscribe is having a lovely day\n")

    assert state.recognized is False
    assert state.login_state == "unknown"
    assert state.connection_state == "unknown"
