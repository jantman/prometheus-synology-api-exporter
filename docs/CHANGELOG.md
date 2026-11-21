# Changelog

Releases before 0.4.0 are described only in [GitHub Releases](https://github.com/jantman/prometheus-synology-api-exporter/releases).

## 0.4.0 (2026-11-21)

No change to exported metrics: every metric name, type, unit, HELP string and label set is identical to 0.3.1 (checked against a DS1621+ on DSM 7.4.1).

* Migrate from [synologydsm-api](https://github.com/hacf-fr/synologydsm-api) 1.0.2, archived upstream, to its maintained successor [py-synologydsm-api](https://github.com/mib1185/py-synologydsm-api) 2.12.0. That library is asyncio/aiohttp-based; the exporter runs it on one long-lived event loop, so the synchronous collector and HTTP server are unchanged.
* Log in to DSM again when its session expires (for example after a DSM reboot). synologydsm-api did this internally; py-synologydsm-api does not.
* The seven DSM API calls per scrape now run concurrently, which shortens `synology_query_time_seconds`.
* `docker stop` now stops the container in under a second and exits cleanly. The image sets `STOPSIGNAL SIGINT`, since Python as PID 1 ignores SIGTERM and Docker used to wait out its 10 second timeout before killing it.
* Docker base image `python:3.11.4-alpine3.18` (Alpine 3.18 is end of life) to `python:3.14.10-alpine3.24`.
* `prometheus-client` 0.20.0 to 0.26.0.
* The Docker `ENTRYPOINT` is now exec form, so arguments such as `-vv` passed to `docker run` reach the exporter (previously they were silently ignored).
* Release workflow: GitHub Actions updated to current major versions (checkout v7, setup-buildx v4, login v4, build-push v7), and the archived `actions/create-release` replaced with `gh release create`.
