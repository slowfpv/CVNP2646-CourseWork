import pytest
from pathlib import Path

from network_monitor import (
    NetworkConfig,
    parse_packet_line,
    is_syn_packet,
    detect_port_scan,
    detect_syn_flood,
    analyze_traffic,
    validate_args
)


@pytest.fixture
def sample_config():
    return NetworkConfig(port_scan_threshold=25, syn_flood_threshold=100)


@pytest.fixture
def valid_packet_line():
    return "192.168.1.5,10.0.0.1,54321,443,TCP,SYN"


@pytest.fixture
def sample_packets():
    return [
        {
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "SYN"
        },
        {
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 54322,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "SYN"
        }
    ]


def test_parse_valid_packet(valid_packet_line):
    packet = parse_packet_line(valid_packet_line)

    assert packet["src_ip"] == "192.168.1.5"
    assert packet["dst_ip"] == "10.0.0.1"
    assert packet["src_port"] == 54321
    assert packet["dst_port"] == 443
    assert packet["protocol"] == "TCP"
    assert packet["flags"] == "SYN"


def test_parse_too_few_fields():
    with pytest.raises(ValueError):
        parse_packet_line("192.168.1.5,10.0.0.1,443")


def test_parse_too_many_fields():
    with pytest.raises(ValueError):
        parse_packet_line("192.168.1.5,10.0.0.1,54321,443,TCP,SYN,EXTRA")


def test_parse_bad_port():
    with pytest.raises(ValueError):
        parse_packet_line("192.168.1.5,10.0.0.1,bad,443,TCP,SYN")


def test_parse_empty_string():
    with pytest.raises(ValueError):
        parse_packet_line("")


def test_parse_extra_whitespace():
    packet = parse_packet_line(" 192.168.1.5 , 10.0.0.1 , 54321 , 443 , tcp , syn ")

    assert packet["src_ip"] == "192.168.1.5"
    assert packet["protocol"] == "TCP"
    assert packet["flags"] == "SYN"


def test_is_syn_packet_true():
    packet = {
        "protocol": "TCP",
        "flags": "SYN"
    }

    assert is_syn_packet(packet) is True


def test_is_syn_packet_false():
    packet = {
        "protocol": "UDP",
        "flags": "SYN"
    }

    assert is_syn_packet(packet) is False


def test_port_scan_below_threshold(sample_packets, sample_config):
    result = detect_port_scan(
        sample_packets,
        "192.168.1.5",
        sample_config.port_scan_threshold
    )

    assert result is False


def test_port_scan_exactly_at_threshold(sample_config):
    packets = []

    for port in range(1, 26):
        packets.append({
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 50000 + port,
            "dst_port": port,
            "protocol": "TCP",
            "flags": "SYN"
        })

    result = detect_port_scan(
        packets,
        "192.168.1.5",
        sample_config.port_scan_threshold
    )

    assert result is False


def test_port_scan_above_threshold(sample_config):
    packets = []

    for port in range(1, 31):
        packets.append({
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 50000 + port,
            "dst_port": port,
            "protocol": "TCP",
            "flags": "SYN"
        })

    result = detect_port_scan(
        packets,
        "192.168.1.5",
        sample_config.port_scan_threshold
    )

    assert result is True


def test_port_scan_empty_list(sample_config):
    result = detect_port_scan(
        [],
        "192.168.1.5",
        sample_config.port_scan_threshold
    )

    assert result is False


def test_syn_flood_below_threshold(sample_packets, sample_config):
    result = detect_syn_flood(
        sample_packets,
        "192.168.1.5",
        sample_config.syn_flood_threshold
    )

    assert result is False


def test_syn_flood_above_threshold(sample_config):
    packets = []

    for number in range(101):
        packets.append({
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 40000 + number,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "SYN"
        })

    result = detect_syn_flood(
        packets,
        "192.168.1.5",
        sample_config.syn_flood_threshold
    )

    assert result is True


def test_syn_flood_mixed_protocols(sample_config):
    packets = []

    for number in range(80):
        packets.append({
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 40000 + number,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "SYN"
        })

    for number in range(50):
        packets.append({
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 50000 + number,
            "dst_port": 53,
            "protocol": "UDP",
            "flags": "SYN"
        })

    result = detect_syn_flood(
        packets,
        "192.168.1.5",
        sample_config.syn_flood_threshold
    )

    assert result is False


def test_syn_flood_multiple_source_ips(sample_config):
    packets = []

    for number in range(101):
        packets.append({
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 40000 + number,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "SYN"
        })

    for number in range(10):
        packets.append({
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "src_port": 50000 + number,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "SYN"
        })

    assert detect_syn_flood(packets, "192.168.1.5", sample_config.syn_flood_threshold) is True
    assert detect_syn_flood(packets, "192.168.1.10", sample_config.syn_flood_threshold) is False


def test_analyze_traffic_full_pipeline(sample_packets, sample_config):
    results = analyze_traffic(sample_packets, sample_config)

    assert "total_packets" in results
    assert "port_scans" in results
    assert "syn_floods" in results
    assert results["total_packets"] == 2


def test_analyze_empty_traffic(sample_config):
    results = analyze_traffic([], sample_config)

    assert results["total_packets"] == 0
    assert len(results["port_scans"]) == 0
    assert len(results["syn_floods"]) == 0


def test_validate_args_negative_threshold(tmp_path):
    sample_file = tmp_path / "traffic.log"
    sample_file.write_text("192.168.1.5,10.0.0.1,54321,443,TCP,SYN")

    class Args:
        input_file = sample_file
        output = Path("results.json")
        port_scan_threshold = -1
        syn_flood_threshold = 100
        log_level = "INFO"
        verbose = False

    with pytest.raises(ValueError):
        validate_args(Args())