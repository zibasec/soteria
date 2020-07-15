# Soteria

![Soteria the Greek God of Safety](./soteria.jpg "Soteria the Greek God of Safety")

A simple script that checks your machine for sane security defaults.

Start by installing [BATS](https://github.com/bats-core/bats-core):

`brew install bats-core`

On Linux you may require `bats`:

`sudo apt install bats`

Then clone or fetch updates to this repo locally:

`git clone git@github.com:zibasec/soteria.git`

Then run the required script according to your OS. For example, on Mac OS:

`chmod +x ./mac-os.sh && sudo ./mac-os.sh`

Any failures can be remediated using the `Fix` comments in the scripts.

Re-run checks until they all pass.

## Audit rules for `auditd`

The file [`linux-auditd-rules.txt`](linux-auditd-rules.txt) is provided for convenience of meeting the checked requirements. To use, add the rules to `audit.rules` with:

```bash
sudo vim /etc/audit/rules.d/audit.rules
sudo augenrules --load
```
