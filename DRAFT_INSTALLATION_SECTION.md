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
