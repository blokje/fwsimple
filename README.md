# fwsimple - Simplified Firewall Configuration

fwsimple is a tool designed to simplify the process of configuring a Linux firewall. It allows you to define your network zones, default policies, and specific firewall rules in human-readable configuration files. fwsimple then translates these definitions into the appropriate commands for a chosen backend firewall system, such as `iptables` or `nftables`.

This approach helps maintain a clear, organized, and easy-to-understand firewall policy, abstracting away the complexities of the underlying firewall commands.

## Table of Contents

- [Installation](#installation)
- [Command-Line Usage](#command-line-usage)
- [Configuration (`fwsimple.cfg`)](#configuration-fwsimplecfg)
  - [`[fwsimple]` Section](#fwsimple-section)
  - [`[policy]` Section](#policy-section)
  - [`[zones]` Section](#zones-section)
- [Rule Definition (`.rule` files)](#rule-definition-rule-files)
  - [Rule Structure](#rule-structure)
  - [Rule Parameters](#rule-parameters)
  - [Examples of Rules](#examples-of-rules)
- [Key Concepts and Processing Logic](#key-concepts-and-processing-logic)
  - [The `global` Zone](#the-global-zone)
  - [Rule Processing Order](#rule-processing-order)
- [Firewall Engines](#firewall-engines)
  - [Supported Engines](#supported-engines)
  - [Engine Operation](#engine-operation)

## Installation

It is recommended to install `fwsimple` using `pip`.

### From PyPI (if available)

If `fwsimple` is published on the Python Package Index (PyPI), you can install it with:

```bash
pip install fwsimple
```

### From source

Alternatively, you can install `fwsimple` from a local source checkout:

1.  Clone the repository:
    ```bash
    git clone <repository_url>
    cd fwsimple
    ```
    (Replace `<repository_url>` with the actual URL of the repository)

2.  Install using `pip`:
    ```bash
    pip install .
    ```
    Or, for development mode (editable install):
    ```bash
    pip install -e .
    ```

### Dependencies

`fwsimple` requires:
- Python 3.x (as indicated by `setup.py` being `python3`)
- The `ipaddress` module (this is part of the standard library since Python 3.3, so no separate installation is usually needed for modern Python versions).

After installation, the command-line tool `fwsimple` will be available in your path.

## Command-Line Usage

Once `fwsimple` is installed, it provides a command-line tool named `fwsimple` to parse your configurations and apply them to the selected firewall engine.

### Basic Execution

To apply your firewall rules:

```bash
fwsimple
```

By default, this command will:
1.  Read the configuration from `/etc/fwsimple/fwsimple.cfg`.
2.  Load all `.rule` files from the `rulesets` directory specified in the configuration.
3.  Generate and execute the necessary commands for the selected `engine` (e.g., `iptables` or `nftables`) to implement the firewall rules.

Ensure you have the necessary permissions (usually root or sudo privileges) to modify firewall rules when running `fwsimple` without `--dry-run`.

```bash
sudo fwsimple
```

### Dry Run Mode

It is highly recommended to perform a dry run before applying changes, especially when modifying firewall rules. The dry run mode will print all the commands that `fwsimple` *would* execute, without actually running them. This allows you to inspect and verify the generated rules.

To perform a dry run:

```bash
fwsimple --dry-run
```
Or, if sudo is normally needed to read all files (though typically not for dry run if paths are accessible):
```bash
sudo fwsimple --dry-run
```

Review the output carefully to ensure it matches your expectations before applying the rules live.

### Specifying a Configuration File (Future/Potential)

Currently, the main `fwsimple` entry point uses a hardcoded path `/etc/fwsimple/fwsimple.cfg`. If future versions allow specifying a custom configuration file path via the command line, the usage would be updated accordingly (e.g., `fwsimple -c /path/to/myconfig.cfg`).

## Configuration (`fwsimple.cfg`)

`fwsimple` uses a central configuration file, typically located at `/etc/fwsimple/fwsimple.cfg` (though you can specify a different path when running `fwsimple` if your version supports it - currently, the main entry point hardcodes this path). This file uses an INI-style format.

It contains three main sections: `[fwsimple]`, `[policy]`, and `[zones]`.

### `[fwsimple]` Section

This section defines core operational parameters for `fwsimple`.

-   **`rulesets`**:
    -   Description: Specifies the directory path where your `.rule` files are stored. `fwsimple` will read all files ending with `.rule` from this location.
    -   Example: `rulesets = /etc/fwsimple/rules`

-   **`engine`**:
    -   Description: Determines which firewall backend `fwsimple` will use to implement the rules.
    -   Supported values:
        -   `iptables`: For generating rules compatible with the traditional iptables firewall.
        -   `nftables`: For generating rules compatible with the modern nftables framework.
    -   Example: `engine = nftables`

### `[policy]` Section

This section defines the default policies for traffic entering or leaving the system through different base chains/directions. These policies are applied if no specific rule matches the traffic.

-   **`in`**:
    -   Description: Default policy for incoming traffic (e.g., to the `INPUT` chain in iptables/nftables).
    -   Accepted values: `accept`, `reject`, `discard`.
    -   Example: `in = reject`

-   **`out`**:
    -   Description: Default policy for outgoing traffic generated by the system itself (e.g., to the `OUTPUT` chain).
    -   Accepted values: `accept`, `reject`, `discard`.
    -   Example: `out = accept`

-   **`forward`**:
    -   Description: Default policy for traffic being forwarded through the system (e.g., to the `FORWARD` chain).
    -   Accepted values: `accept`, `reject`, `discard`.
    -   Example: `forward = reject`

    *Note on policy actions:*
    *   `accept`: Allows the traffic.
    *   `reject`: Blocks the traffic and sends a rejection notification (e.g., ICMP port unreachable or TCP reset).
    *   `discard`: Silently drops the traffic with no notification. (This is often referred to as `DROP` in iptables/nftables contexts; `fwsimple` uses `discard` as its keyword which maps to `DROP` in iptables and `drop` in nftables).

### `[zones]` Section

This section is used to define network zones, which are essentially named groups of network interfaces and/or source IP addresses/networks. Rules are then applied to these zones.

-   **Syntax**:
    -   Simple interface assignment: `zonename = interface_name`
        -   Example: `public = eth0`
    -   Multiple interfaces for one zone: `zonename = interface1,interface2,interface3`
        -   Example: `internal_ports = eth1,eth2`
    -   Interface with source IP/network restriction: `zonename = interface_name:source_ip/mask`
        -   This means traffic arriving on `interface_name` specifically from `source_ip/mask` will belong to this zone for rule processing.
        -   Example: `dmz_lan = eth0:192.168.100.0/24`
    -   Multiple interface/source definitions for one zone: `zonename = if1:src1/mask1,if2:src2/mask2,...`
        -   Example: `vpn_access = tun0:10.8.0.0/24,tun1:10.9.0.0/24`
    -   A single zone can also combine simple interfaces and interface:source pairs:
        -   Example: `trusted_access = eth1,eth0:172.16.0.0/24`

-   **Order of Evaluation**: When multiple zone definitions could potentially match incoming traffic (e.g., a generic `public = eth0` and a more specific `dmz_lan = eth0:192.168.100.0/24`), `fwsimple` prioritizes more specific definitions (those with source IP/network restriction) over general interface-only definitions for the same interface.

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

## Key Concepts and Processing Logic

Understanding a few key concepts can help in designing effective firewall policies with `fwsimple`.

### The `global` Zone

-   `fwsimple` internally creates a special zone named `global`.
-   This zone acts as a default catch-all. If traffic does not match any specific zone expressions you've defined in the `[zones]` section of `fwsimple.cfg`, it will fall into the `global` zone for each direction (`ZONE_IN_global`, `ZONE_OUT_global`, `ZONE_FWD_global`).
-   Rules can be explicitly assigned to the `global` zone (e.g., `zone = global`) if you want to define baseline rules that apply to any traffic not matching a more specific zone.
-   By default, the `global` zone is linked to the base `input`, `output`, and `forward` chains without any interface or IP restrictions.

### Rule Processing Order

`fwsimple` processes and applies rules in a specific order, which is important for the final behavior of your firewall:

1.  **Initialization (`init`)**: The selected engine first initializes the firewall (e.g., flushes old rules, sets up base tables/chains, applies sane default rules like loopback, conntrack, and essential ICMP types).
2.  **Zone Creation**: Chains for all defined zones (including `global` and those in `fwsimple.cfg`) are created for each direction (e.g., `ZONE_IN_public`, `ZONE_OUT_public`, `ZONE_FWD_public`).
3.  **Zone Expression Linking**: Rules are added to the base `input`, `output`, and `forward` chains to direct traffic to the appropriate zone chains. `fwsimple` sorts these zone expressions, generally prioritizing more specific definitions (e.g., interface with IP) over broader ones (interface only).
4.  **Rule Application**: User-defined rules from `.rule` files are processed and added to their respective zone chains.
    -   **Grouping by Action**: `fwsimple` first groups your rules by their `action` type. The typical processing order for actions is:
        1.  `discard` rules
        2.  `reject` rules
        3.  `accept` rules
    -   Within each action group, the order of rules might depend on the order they are read from the rule files or their names. It's best to design rules to be as independent of subtle ordering as possible, relying on specificity of matches.
5.  **Zone Closing**: A `return` rule is typically added to the end of each user-defined zone chain (and the `global` zone chains), allowing traffic that didn't match any rule in that zone to return to the base chain for further processing (e.g., to eventually hit the default policy).
6.  **Default Policy Application**: Finally, the default policies defined in the `[policy]` section of `fwsimple.cfg` are applied to the base `input`, `output`, and `forward` chains. These catch any traffic that hasn't been handled by specific rules or zone logic.

Understanding this flow, especially the action-based grouping of rules, is crucial for predicting how traffic will be evaluated.

## Firewall Engines

`fwsimple` uses a modular engine system to translate your abstract zone and rule definitions into the specific commands required by different firewall backends. You select the active engine using the `engine` setting in the `[fwsimple]` section of your `fwsimple.cfg` file.

### Supported Engines

-   **`iptables`**
    -   Description: This engine generates rules for the traditional Linux `iptables` firewall framework. It supports IPv4 (`iptables`) and IPv6 (`ip6tables`) rules.
    -   Usage: Set `engine = iptables` in `fwsimple.cfg`.

-   **`nftables`**
    -   Description: This engine generates rules for `nftables`, the modern successor to `iptables` in the Linux kernel. It uses the `inet` family to support both IPv4 and IPv6 rules within a single ruleset structure.
    -   Usage: Set `engine = nftables` in `fwsimple.cfg`.

### Engine Operation

When `fwsimple` runs, the chosen engine is responsible for:
1.  Initializing the firewall (flushing old rules, setting up base tables/chains, applying essential default rules).
2.  Creating chains or equivalent structures for each defined zone.
3.  Translating `fwsimple` rule definitions into the specific syntax and commands of the backend (e.g., `iptables -A ...` or `nft add rule ...`).
4.  Applying default policies.

The `--dry-run` mode is invaluable for seeing the exact commands the selected engine will generate without actually applying them.
