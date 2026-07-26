# Bundled GeoIP database

`dbip-country-lite.mmdb` is the **DB-IP "IP to Country Lite"** database, shipped
with Aegis so country geolocation (the dashboard world map + `[geoip]`
country-deny rules) works out of the box with no key and no configuration.

- **Source:** https://db-ip.com/db/download/ip-to-country-lite
- **Format:** MaxMind DB (`.mmdb`) — read by the `maxminddb` crate.
- **License:** Creative Commons Attribution 4.0 International (CC BY 4.0).

## Attribution (required by CC BY 4.0)

> IP geolocation by DB-IP (https://db-ip.com) — CC BY 4.0

This attribution is also surfaced in the admin panel on the GeoIP page.

## How it's used

- `install.sh` copies this file to `/var/lib/aegis/geoip/dbip-country-lite.mmdb`
  (writable by the service user) on install/update, using `cp -n` so a
  panel-refreshed database is never clobbered.
- The proxy resolves the database via `geoip::resolve_country_db_path()`:
  explicit `[geoip] db_path` → `AEGIS_GEOIP_PATH` → bundled location.
- The panel's **Update database** button (`POST /admin/api/geoip/update`)
  downloads the current month's release from db-ip, swaps it atomically, and
  restarts the service to load it.

## Refreshing the bundled copy

db-ip publishes a new free build monthly. To refresh the copy committed here:

```sh
curl -fL "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz" \
  | gunzip > data/geoip/dbip-country-lite.mmdb
```
