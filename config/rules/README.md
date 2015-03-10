Rules
=====

Rules are defined in simple ini files with a simple syntax

Rule types
----------
There are a few rule types:
* filter
* nat

Firewall rules
--------------
Firewall rules are defined by the type filter, please note that whenever
the type is not defined it is implicitly defined as filter.

Permitted parameters:
* zone (required)
* source
* destination
* port
* protocol
* action 
* log

Rules are loaded all at once in memory, compiled and afterwards inserted in 
iptables, please not that the following order applies based on action:
1. Discard
2. Reject
3. Accept


### zone
The firewall zone to add this rule to.

### source
The source address(es) where the traffic is coming from. Multiple addresses can be seperated with a comma, both IPv4 and IPv6 addresses can be provided.

### destination
The destination address(es) for the traffic. Multiple addresses can be seperated with a comma, both IPv4 and IPv6 addresses can be provided.

### port
The port the traffic is going to. Multiple ports can be seperated with a comma, ranges can be specified with a '-'.

### protocol
The protocol, default is TCP.

Allowed protocols are:
* icmp
* tcp
* udp

### action
The action to undertake with this rule, default action is accept

Allowed actions are:
* accept
* reject
* discard

#### accept 
The traffic will be accepted

#### reject 
The traffic will be rejected with an ICMP icmp-port-unreachable for a 
maximum of 2 tries per second after which traffic will be dropped

#### discard 
Drop all traffic and dont even reply

### log
Log traffic on this interface

## Example
The following example will allow traffic within the zone global from 192.168.0.10 and fc00:192:168:0::10 to 192.160.0.50 and fc00:192:168:0::50 for tcp port 22 and 22022
```dosini
[ssh]
zone = global
from = 192.168.0.10,fc00:192:168:0::10
to = 192.168.0.50,fc00:192:168:0::50
port = 22,22022
protocol = tcp
action = accept
log = false
```

### Mixing of addresses
Please not that is is possible to combine IPv4 and IPv6 addresses in both source and destination, fwsimple will take care of this and will add rules for all possible combinations. Please note that when you mix source and destination with different protocol IP versions no suitable rules can be generated and the rule would be ignored.

#### Examples
*Mixed wrong addresses*
```dosini
from = 192.168.0.10
to = fc00:192:168:0::50
```

The following IP sets will be generated with the following ini
```dosini
from = 192.168.0.10,192.168.0.11,fc00::10
to = 192.168.1.20,fc00::51,fc00::50
```

| From         | To           | Version |
| ------------ | ------------ | ------- |
| 192.168.0.10 | 192.168.1.20 | IPv4    |
| 192.168.0.11 | 192.168.1.20 | IPv4    |
| fc00::10     | fc00::51     | IPv6    |
| fc00::10     | fc00::50     | IPv6    |

