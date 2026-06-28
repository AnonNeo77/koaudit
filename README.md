# KOAUDIT

Static analysis tool for Linux kernel modules.

KOAUDIT inspects compiled Linux kernel modules (`.ko`) and reports suspicious behaviors commonly associated with kernel rootkits, insecure drivers, and malicious modules. Analysis is performed statically — modules are never loaded or executed.

---

## Features

* Static analysis of Linux kernel modules (`.ko`)
* ELF validation and metadata inspection
* Detection of common kernel hook patterns
* Detection of write-protection bypasses
* Detection of credential manipulation APIs
* Detection of custom IOCTL interfaces
* Detection of dynamic symbol resolution
* Detection of suspicious module metadata
* JSON and HTML report output
* Lightweight with no external services

---

## Installation

```bash
git clone https://github.com/<username>/koaudit.git
cd koaudit

pip install -r requirements.txt
```

---

## Usage

```bash
python3 koaudit.py module.ko
```

Verbose output:

```bash
python3 koaudit.py --verbose module.ko
```

JSON report:

```bash
python3 koaudit.py --json module.ko
```

HTML report:

```bash
python3 koaudit.py --html module.ko
```

---

## Current Detection Rules

* Write-protection bypasses
* Kernel tracing hooks
* Credential manipulation APIs
* Custom IOCTL interfaces
* Dynamic symbol resolution
* Module metadata anomalies

---

## Limitations

* Static analysis only.
* Modules are **not** executed.
* A clean result does not guarantee a module is safe.
* Detection is based on implemented heuristics and may not identify every technique.

---

## Testing

Run the test suite:

```bash
python3 -m unittest discover tests
```

---

## Contributing

Bug reports, improvements, and pull requests are welcome.

---

## License

Released under the MIT License.
