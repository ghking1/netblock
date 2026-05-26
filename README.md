# netblock
Command line tools for windows network block manage using WFP, no backend service needed.

download from: https://github.com/ghking1/netblock/releases

## Usage

C:\Windows\System32>netblock.exe -h
```
netblock <command> [options]

Commands:
  add    Add a blocking/filtering rule
  del    Delete rule(s)
  list   List all rules managed by netblock

Options for 'add':
  -n <name>         Rule name (for later management; default: auto-generated UUID)
  -p <path>         Program absolute path (include .exe; default: all programs)
  -a <ip/cidr>      Remote IP address (IPv4/IPv6, e.g. 192.168.1.1 or 2001:db8::/32)
  -l <port|range>   Local port (e.g. 80; 8000-9000; 81,82,83; 81,82-85; default: all)
  -r <port|range>   Remote port (same format as -l; default: all)
  -e <block|allow>  Action (default: block)
  -d <in|out|both>  Traffic direction (default: both)
  -t                Set as temporary rule (default: persistent)

Options for 'del':
  -n <name>         Delete by rule name (recommended)
  -p <path>         Delete all rules matching this program path (batch)

Note: 'add' requires at least one filter condition (-p, -a, -l, or -r).
```


## Features

- AI-friendly command-line interface
- Directly uses low-level Windows APIs, with no backend service required
- Does not rely on Windows Firewall, and remains effective even when the firewall is disabled

## License

This project is licensed under the MIT License.
