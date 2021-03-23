# Webhook-cd
[![linting](https://github.com/jon4hz/webhook-cd/actions/workflows/python-app.yml/badge.svg)](https://github.com/jon4hz/webhook-cd/actions/workflows/python-app.yml)
## About
This is a simple webhook server, written in python. Once the webhook is triggered (from a GitHub Action for example), the script automatically updates predefined containers using [watchtower](https://containrrr.dev/watchtower).

## How to
\- More notes than instructions \-
* Create venv
* Create systemd service
* Create config file
* Enable & start systemd service
