from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class OracleInterface:
    name: str | None = None
    ip: str | None = None
    mask: str | None = None
    subnet: str | None = None


@dataclass(frozen=True, slots=True)
class OracleDevice:
    name: str
    device_type: str
    model: str
    ips: tuple[str, ...] = ()
    interfaces: tuple[OracleInterface, ...] = ()
    subnets: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OracleLink:
    left: str
    right: str


@dataclass(frozen=True, slots=True)
class OracleTopology:
    source_file: str
    packet_tracer_version: str
    saved_on_os: str
    devices: tuple[OracleDevice, ...]
    links: tuple[OracleLink, ...]
    baseline_source_file: str | None = None
    vlan_context: str | None = None
    notes: tuple[str, ...] = ()


TRIAL_PKT_ORACLE = OracleTopology(
    source_file="trial.pkt",
    packet_tracer_version="9.0.0",
    saved_on_os="Windows 10 Pro 22H2",
    devices=(
        OracleDevice(name="Switch0", device_type="switch", model="Cisco 2960-24TT"),
        OracleDevice(name="Switch1", device_type="switch", model="Cisco 2960-24TT"),
        OracleDevice(
            name="PC0",
            device_type="pc",
            model="PC-PT",
            ips=("192.168.1.1",),
            subnets=("192.168.1.0/24",),
        ),
        OracleDevice(
            name="PC1",
            device_type="pc",
            model="PC-PT",
            ips=("192.168.1.2",),
            subnets=("192.168.1.0/24",),
        ),
    ),
    links=(
        OracleLink(left="PC0", right="Switch0"),
        OracleLink(left="Switch0", right="Switch1"),
        OracleLink(left="Switch1", right="PC1"),
    ),
    vlan_context="VLAN 1",
    notes=(
        "No router present.",
        "PCs are in the same subnet.",
    ),
)

TRIAL_IPCHANGE_PKT_ORACLE = OracleTopology(
    source_file="trial-ipchange.pkt",
    packet_tracer_version="9.0.0",
    saved_on_os="Windows 10 Pro 22H2",
    baseline_source_file="trial.pkt",
    devices=(
        OracleDevice(name="Switch0", device_type="switch", model="Cisco 2960-24TT"),
        OracleDevice(name="Switch1", device_type="switch", model="Cisco 2960-24TT"),
        OracleDevice(
            name="PC0",
            device_type="pc",
            model="PC-PT",
            ips=("192.168.1.1",),
            subnets=("192.168.1.0/24",),
        ),
        OracleDevice(
            name="PC1",
            device_type="pc",
            model="PC-PT",
            ips=("192.168.1.3",),
            subnets=("192.168.1.0/24",),
        ),
    ),
    links=TRIAL_PKT_ORACLE.links,
    vlan_context="VLAN 1",
    notes=(
        "No router present.",
        "This sample differs from trial.pkt by the second PC IP only.",
    ),
)

TRIAL_ROUTER_PKT_ORACLE = OracleTopology(
    source_file="trial-router.pkt",
    packet_tracer_version="9.0.0",
    saved_on_os="Windows 10 Pro 22H2",
    baseline_source_file="trial.pkt",
    devices=(
        OracleDevice(name="Switch0", device_type="switch", model="Cisco 2960-24TT"),
        OracleDevice(name="Switch1", device_type="switch", model="Cisco 2960-24TT"),
        OracleDevice(
            name="PC0",
            device_type="pc",
            model="PC-PT",
            subnets=("192.168.1.0/24",),
        ),
        OracleDevice(
            name="PC1",
            device_type="pc",
            model="PC-PT",
            subnets=("192.168.2.0/24",),
        ),
        OracleDevice(
            name="Router0",
            device_type="router",
            model="Cisco 2901",
            interfaces=(
                OracleInterface(
                    name="GigabitEthernet0/0",
                    ip="192.168.1.254",
                    mask="255.255.255.0",
                    subnet="192.168.1.0/24",
                ),
                OracleInterface(
                    name="GigabitEthernet0/1",
                    ip="192.168.2.254",
                    mask="255.255.255.0",
                    subnet="192.168.2.0/24",
                ),
            ),
            subnets=("192.168.1.0/24", "192.168.2.0/24"),
        ),
    ),
    links=(
        OracleLink(left="PC0", right="Switch0"),
        OracleLink(left="Switch0", right="Router0"),
        OracleLink(left="Router0", right="Switch1"),
        OracleLink(left="Switch1", right="PC1"),
    ),
    notes=(
        "Single router between two switched LANs.",
        "Do not infer or generate RIP; one router routes between its directly connected interfaces.",
        "PC default gateways are 192.168.1.254 and 192.168.2.254 respectively.",
    ),
)


ORACLE_REGISTRY: dict[str, OracleTopology] = {
    TRIAL_PKT_ORACLE.source_file.lower(): TRIAL_PKT_ORACLE,
    "trial.pkz": TRIAL_PKT_ORACLE,
    TRIAL_IPCHANGE_PKT_ORACLE.source_file.lower(): TRIAL_IPCHANGE_PKT_ORACLE,
    TRIAL_ROUTER_PKT_ORACLE.source_file.lower(): TRIAL_ROUTER_PKT_ORACLE,
}


def get_oracle_for_file(source_file: str) -> OracleTopology | None:
    return ORACLE_REGISTRY.get(source_file.lower())
