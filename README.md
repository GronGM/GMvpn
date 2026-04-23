# vpnclient-prototype

Linux-first open-source VPN client prototype focused on:
- signed config manifests
- last-known-good config cache
- transport abstraction and failover
- endpoint cooldown and incident flags with TTL
- startup recovery and support bundles
- dry-run Linux network planning and dry-run userspace data plane

## Run demo

```bash
cd /mnt/data/vpn_client_prototype
python -m vpnclient.cli.demo
```

## Run tests

```bash
cd /mnt/data/vpn_client_prototype
python -m pytest
```
