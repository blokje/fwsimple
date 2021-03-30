from ipaddress import IPv4Network, IPv6Network
from typing import Tuple, Union
from typing_extensions import Literal

TrafficDirection = Literal["in", "out", "forward"]
IpNetwork = Union[IPv4Network, IPv6Network]
IpSourceDestMapping = Union[
    Tuple[IPv4Network, IPv4Network],
    Tuple[IPv6Network, IPv6Network],
    Tuple[None, Union[IPv4Network, IPv6Network]],
    Tuple[Union[IPv4Network, IPv6Network], None],
    Tuple[None, None]
]
FilterAction = Literal["accept", "reject", "discard"]
FilterProtocol = Literal["tcp", "udp", "icmp"]