# EXPERIMENTAL/ALPHA/UNSUPPORTED prometheus-synology-api-exporter

[![Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip) [![Docker Pulls](https://img.shields.io/docker/pulls/jantman/prometheus-synology-api-exporter)](https://hub.docker.com/repository/docker/jantman/prometheus-synology-api-exporter) [![GitHub last commit](https://img.shields.io/github/last-commit/jantman/prometheus-synology-api-exporter)](https://github.com/jantman/prometheus-synology-api-exporter)

Prometheus exporter for Synology DSM using the API for metrics, via the [synologydsm-api](https://pypi.org/project/synologydsm-api/) Python package ([github](https://github.com/hacf-fr/synologydsm-api)).

**WARNING** This code is to be considered experimental/alpha and essentially **unsupported**. I'm writing and using this at home, not in a production setting. Most importantly, I only have one Synology NAS, so I have no way of testing the many failure conditions. Since there aren't any docs that I can find for the API responses, many of the string-based statuses returned by the API are currently implemented as boolean enums (OK/normal or... not) because I have no way of determining the full list of possible values. **If you would like to take over this project,** please let me know via an issue.

I wrote this because the common way of monitoring Synology NASes, via the [snmp_exporter](https://github.com/prometheus/snmp_exporter), doesn't expose the metric that I find most important: per-disk and per-volume IO utilization percentage. I was already monitoring this via a Python script before I started using Prometheus, so this is based on that original script.

## Usage

This is really only intended to be run via Docker, ideally on the DSM itself. To run on port 8080:

```
docker run -p 8080:8080 \
    -e DSM_IP=YOUR_DSM_IP \
    -e DSM_USER=YOUR_DSM_USERNAME \
    -e DSM_PASS='YOUR_DSM_PASSWORD' \
    jantman/prometheus-synology-api-exporter:latest
```

### Environment Variables

* `DSM_IP` (**required**) - The IP address or hostname to connect to the DSM API (web UI) on.
* `DSM_USER` (**required**) - The username for connecting to the DSM. It's recommended that this is a read-only user.
* `DSM_PASS` (**required**) - The password for `DSM_USER`.
* `DSM_PORT` (*optional*) - The port number to connect to the DSM API on. Defaults to 5000.
* `DSM_USE_HTTPS` (*optional*) - Set to `true` if you want to connect over HTTPS. Defaults to unset (plain HTTP).
* `DSM_VERIFY_SSL` (*optional*) - Set to `true` if you want to verify SSL. Defaults to unset (verify False).
* `DSM_TIMEOUT_SEC` (*optional*) - Timeout in seconds for DSM API calls. Defaults to 30.

### Debugging

For debugging, append `-vv` to your `docker run` command, to run the entrypoint with debug-level logging.

## Development

Clone the repo, then in your clone:

```
python3 -mvenv venv
source venv/bin/activate
pip install synologydsm-api==1.0.2 prometheus-client==0.17.0
```


### Release Process

Tag the repo. [GitHub Actions](https://github.com/jantman/prometheus-synology-api-exporter/actions) will run a Docker build, push to Docker Hub and GHCR (GitHub Container Registry), and create a release on the repo.
