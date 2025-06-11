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
