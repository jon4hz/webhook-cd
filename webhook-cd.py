#!./venv/bin/python
#
# Author: jon4hz
# Date: 24.03.2021
# Desc: Webhook for cd
###################################################################################################
# loggging
import logging
logging.basicConfig(level=logging.INFO,
                    format="{asctime} [{levelname:8}] {process} {thread} {module}: {message}",
                    style="{")

try:
    from hashlib import sha1
    import hmac
    import docker
    import importlib
    from flask import Flask, request
    from waitress import serve
    import config
except ImportError as e:
    logging.error(f'Could not import all modules - {e}')
    exit()


app = Flask(__name__)


def verify_signature(req, secret) -> bool:
    # check the signature or return False
    try:
        received_sign = req.headers.get('X-Hub-Signature').split('sha1=')[-1].strip()
        secret = secret.encode()
        expected_sign = hmac.HMAC(key=secret, msg=req.data, digestmod=sha1).hexdigest()
        return hmac.compare_digest(received_sign, expected_sign)
    except Exception as e:
        print(e)
        return False


def update_containers(containers) -> None:
    command = f'--run-once {" ".join(containers)}'
    # start watchtower container
    client.containers.run(
        image='containrrr/watchtower',
        command=command,
        volumes={'/var/run/docker.sock': {'bind': '/var/run/docker.sock', 'mode': 'rw'}},
        detach=True,
        remove=True
        )


@app.route('/webhooks/containers', methods=['POST'])
def main():
    if request.method == 'POST':
        try:
            importlib.reload(config)
        except Exception as e:
            logging.error(f'Could not reload config - {e}')
        if verify_signature(request, config.WEBHOOK_SECRET):
            update_containers(config.DOCKER_CONTAINERS)
            print(config.DOCKER_CONTAINERS)
            return 'Success', 200
        return 'Forbidden', 403
    return 'Not allowed', 405


if __name__ == '__main__':
    # create docker client
    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        logging.error(f'Could not create docker client - {e}')
    # create webhook server
    serve(app, host='0.0.0.0', port=8888)
