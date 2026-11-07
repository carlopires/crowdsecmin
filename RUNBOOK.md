# Runbook (quick reference)

Full operational guide: [docs/operations.md](docs/operations.md).
Configuration reference: [docs/configuration.md](docs/configuration.md).

```bash
# install
sudo dpkg -i cslite_0.1.0_amd64.deb
sudoedit /etc/cslite/cslite.yaml
sudo cslite check-config

# Mode B cutover (keep the Go bouncer, replace the engine)
sudo systemctl stop crowdsec
sudo systemctl enable --now cslite
sudo cslite reconcile --dry-run && sudo cslite reconcile
cslite status

# rollback (sets are left intact)
sudo systemctl stop cslite && sudo systemctl enable --now crowdsec
```

See `docs/operations.md` for Mode A, nftables, local detection, verification,
measurement, and gotchas.
