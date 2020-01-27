![Soteria the Greek God of Safety](./soteria.jpg "Soteria the Greek God of Safety")

# Soteria

A simple script that checks your macbook for sane security defaults.

Start by installing BATS

`brew install bats-core`

Then clone or fetch updates to this repo locally

`git clone git@github.com:zibasec/soteria.git`

Then run

`sudo bats run.sh`

Any failures can be remediated using the Fix comment in `run.sh`

Re-run checks until they all pass.
