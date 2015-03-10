Rules
####=

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
  * source
  * destination
  * port
  * protocol
  * action 
  * log

Rules are loaded all at once in memory, compiled and afterwards inserted in 
iptables, please not that the following order applies based on action:
  1 Discard
  2 Reject
  3 Accept

### source
The source address(es) where the traffic is coming from

### destination
The destination address(es) where the traffic is going to

### port
The port the traffic is going to

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
