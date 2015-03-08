""" Data contains all the constants """
BASIC_IPTABLES_INIT = [
    ['-F'],    # Flush all chains
    ['-X'],    # Delete user-defined chains
    ['-Z'],    # Zero counters
    ['-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
    ['-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
    ['-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ['-A', 'FORWARD', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ['-A', 'OUTPUT', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ['-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'INVALID', '-j', 'DROP']
]

BASIC_IP4TABLES_INIT = [
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '8', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Echo Request'],
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '3/4', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Fragmentation needed'],
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '3/3', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Port unreachable'],
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '3/1', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Host unreachable'],
    ['-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '4', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMP] Source Quench (RFC 792)']
]

BASIC_IP6TABLES_INIT = [
    ['-A', 'INPUT', '-p', '59', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[IPv6] No next header RFC2460'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '2', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Packet too big'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '3', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Time exceeded'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '133', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Router sollicitation'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '134', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Router advertisement'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '135', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Neighbor sollicitation'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '136', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Neighbor advertisement'],
    ['-A', 'INPUT', '-p', 'icmpv6', '-m', 'icmpv6', '--icmpv6-type', '128', '-j', 'ACCEPT', '-m', 'comment', '--comment', '[ICMPv6] Echo Request']
]

DIRECTION = {'in': 'IN', 'out': 'OUT', 'forward': 'FWD'}

EXEC_IPTABLES = 1
EXEC_PF = 2
EXEC_MAP = {
    'iptables': EXEC_IPTABLES,
    'pf': EXEC_PF,
}

GLOBAL_ZONE_NAME = 'global'

IPTABLES_ACTIONS = {'accept': 'ACCEPT', 'reject': 'REJECT', 'discard': 'DROP'}
IPTABLES_DIRECTION = {'in': 'INPUT', 'out': 'OUTPUT', 'forward': 'FORWARD'}

PROTO_IPV4 = 1
PROTO_IPV6 = 2

