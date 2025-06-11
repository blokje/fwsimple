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
