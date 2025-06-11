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
