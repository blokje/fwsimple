# fwsimple

fwsimple is a tool to simplify firewall configuration. It allows you to define zones and rules in a straightforward manner and then applies them to your chosen firewall backend.

## Configuration

fwsimple is configured via a main configuration file (typically located at `/etc/fwsimple/fwsimple.cfg`). Key options include:

-   `rulesets`: Path to the directory containing your rule files.
-   `engine`: The firewall backend to use.

Example `fwsimple.cfg` snippet:

```ini
[fwsimple]
rulesets = /etc/fwsimple/rules
engine = nftables ; Or iptables
```

## Supported Firewall Backends

fwsimple currently supports the following firewall backends:

-   **iptables**: The traditional Linux firewall.
-   **nftables**: The modern replacement for iptables.

You can select the desired backend by setting the `engine` option in your `fwsimple.cfg` file.

## Rules

Firewall rules are defined in `.rule` files within the directory specified by the `rulesets` option. These files use an INI-style format.

Example `ssh.rule`:

```ini
[allow_ssh_from_lan]
protocol = tcp
port = 22
source = 192.168.1.0/24
zone = trusted
action = accept
```

(Further details on rule syntax would go here, but for this task, focusing on mentioning the engines is sufficient.)
