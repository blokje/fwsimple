## Rule Definition (`.rule` files)

Firewall rules in `fwsimple` are defined in files with a `.rule` extension, located in the directory specified by the `rulesets` option in `fwsimple.cfg`. These files use an INI-style format, where each section defines a single rule.

### Rule Structure

Each rule is defined within its own section, named by the rule itself. This name is primarily for organization and logging.

```ini
[descriptive_rule_name_example]
# Rule parameters go here
...
```
The rule name (e.g., `descriptive_rule_name_example`) will be used in comments within the generated firewall rules (iptables/nftables) and can appear in log messages if logging is enabled for the rule.

### Rule Parameters

The following parameters can be specified for each rule:

-   **`zone`** (Required)
    -   Description: The name of the zone (defined in `fwsimple.cfg`) to which this rule applies. Traffic must be associated with this zone (based on interface/source IP) for the rule to be evaluated.
    -   Example: `zone = public`

-   **`direction`** (Required, defaults to `in` if not specified)
    -   Description: Specifies the direction of traffic this rule applies to. The rule will be added to the corresponding directional chain of the specified `zone` (e.g., `ZONE_IN_public`, `ZONE_OUT_public`, `ZONE_FWD_public`).
    -   Values: `in`, `out`, `forward`.
    -   Example: `direction = in`

-   **`protocol`** (Optional)
    -   Description: The network protocol.
    -   Values: `tcp`, `udp`, `icmp` (for IPv4 ICMP), `icmpv6` (for IPv6 ICMP), or a numeric protocol number. If omitted, the rule applies to all protocols (though this is often combined with port-less rules and can have broad implications).
    -   Example: `protocol = tcp`

-   **`port`** (Optional)
    -   Description: The destination port for `tcp` or `udp` protocols. Can be a single port, a comma-separated list of ports, or a port range.
    -   Examples:
        -   `port = 80`
        -   `port = 80,443`
        -   `port = 1024-2000`
        -   `port = 22,1000-1010,3000`
    -   Note: If specifying multiple ports or a range, also see the `multiport` option.

-   **`multiport`** (Optional, defaults to `false`)
    -   Description: Influences how lists or ranges in the `port` parameter are handled, particularly for the `iptables` engine (which uses the `multiport` match module). For `nftables`, set notation handles this naturally. It's good practice to set `multiport = true` if you are specifying a list or range in `port` to ensure consistent behavior or intent.
    -   Values: `true`, `false`.
    -   Example: `multiport = true`

-   **`source`** (Optional)
    -   Description: The source IP address or network (CIDR notation) from which the traffic originates. Can be IPv4 or IPv6.
    -   Examples:
        -   `source = 192.168.1.100`
        -   `source = 10.0.0.0/8`
        -   `source = 2001:db8::1`
        -   `source = 2001:db8:cafe::/48`

-   **`destination`** (Optional)
    -   Description: The destination IP address or network (CIDR notation) to which the traffic is addressed. Can be IPv4 or IPv6.
    -   Examples: (similar to `source`)
        -   `destination = 8.8.8.8`

-   **`action`** (Required)
    -   Description: The action to take if the traffic matches the rule.
    -   Values:
        -   `accept`: Allow the traffic.
        -   `reject`: Block the traffic and send a rejection notification.
        -   `discard`: Silently drop the traffic.
    -   Example: `action = accept`

-   **`log`** (Optional, defaults to `false`)
    -   Description: If set to `true`, matching traffic will be logged by the firewall backend (e.g., via kernel logs).
    -   Values: `true`, `false`.
    -   Example: `log = true`
    -   Note: Log messages will typically include the rule name as a prefix.

-   **`country`** (Optional)
    -   Description: Restrict traffic to a specific source (for `direction = in`) or destination (for `direction = out`) country using GeoIP lookup. Requires appropriate GeoIP setup for your chosen firewall engine and that the engine supports it (e.g., `iptables` with `xt_geoip`; `nftables` support via this keyword is not implemented in the current `fwsimple` engine).
    -   Values: A two-letter ISO 3166-1 alpha-2 country code (e.g., `US`, `DE`).
    -   Example: `country = US`

### Examples of Rules

**1. Allow SSH from a specific LAN IP to the 'trusted' zone:**
```ini
[allow_ssh_from_mgmt_host]
zone = trusted
direction = in
protocol = tcp
port = 22
source = 192.168.1.50
action = accept
```

**2. Allow HTTPS traffic to the 'public' zone, with logging:**
```ini
[allow_https_public_logged]
zone = public
direction = in
protocol = tcp
port = 443
action = accept
log = true
```

**3. Allow UDP traffic on multiple ports to a 'servers' zone:**
```ini
[allow_custom_udp_services]
zone = servers
direction = in
protocol = udp
port = 12000,12005,12010-12020
multiport = true
action = accept
```

**4. Reject outgoing traffic from 'iot' zone to a specific external IP, for logging:**
```ini
[block_iot_to_specific_external_ip]
zone = iot
direction = out
destination = 198.51.100.10
action = reject
log = true
```

**5. Allow ICMP (ping) from the 'internal' zone:**
```ini
[allow_ping_from_internal]
zone = internal
direction = in
protocol = icmp
action = accept
```
