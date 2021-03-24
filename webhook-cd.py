#!./venv/bin/python
#
# Author: jon4hz
# Date: 24.03.2021
# Desc: Webhook for cd
###################################################################################################
# loggging
import logging
logging.basicConfig(level=logging.INFO,
                    format="{asctime} [{levelname:8}] {module}: {message}",
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


def set_properties(old, new):
    # stolen from ouroboros (thanks!)
    """Store object for spawning new container in place of the one with outdated image"""
    properties = {
        'name': old.name,
        'hostname': old.attrs['Config']['Hostname'],
        'user': old.attrs['Config']['User'],
        'detach': True,
        'domainname': old.attrs['Config']['Domainname'],
        'tty': old.attrs['Config']['Tty'],
        'ports': None if not old.attrs['Config'].get('ExposedPorts') else [
            (p.split('/')[0], p.split('/')[1]) for p in old.attrs['Config']['ExposedPorts'].keys()
        ],
        'volumes': None if not old.attrs['Config'].get('Volumes') else [
            v for v in old.attrs['Config']['Volumes'].keys()
        ],
        'working_dir': old.attrs['Config']['WorkingDir'],
        'image': new.tags[0],
        'command': old.attrs['Config']['Cmd'],
        'host_config': old.attrs['HostConfig'],
        'labels': old.attrs['Config']['Labels'],
        'entrypoint': old.attrs['Config']['Entrypoint'],
        'environment': old.attrs['Config']['Env'],
        'healthcheck': old.attrs['Config'].get('Healthcheck', None)
    }

    return properties


def get_containers(container_names):
    containers = []
    for name in container_names:
        try:
            containers.append(client.containers.get(name))
        except docker.errors.NotFound as e:
            logging.error(e)

    return containers


def remove_container(container):
    try:
        container.stop()
    except docker.errors.APIError as e:
        logging.error(e)


def stop_container(container):
    try:
        container.kill()
    except docker.errors.APIError as e:
        logging.error(e)


def recreate_containers(container_names):
    containers = get_containers(container_names)
    for container in containers:
        current_image = container.image
        image_name = container.attrs['Config']['Image']
        new_image = client.images.pull(image_name)
        if new_image.id != current_image.id:
            properties = set_properties(container, new_image)
            # remove old container
            stop_container(container)
            remove_container(container)
            # create new container
            created = client.api.create_container(**properties)
            new_container = client.containers.get(created.get("Id"))
            # connect the new container to all networks of the old container
            for network_name, network_config in container.attrs['NetworkSettings']['Networks'].items():
                network = client.networks.get(network_config['NetworkID'])
                try:
                    network.disconnect(new_container.id, force=True)
                except docker.errors.APIError:
                    pass
                new_network_config = {
                    'container': new_container,
                    'aliases': network_config['Aliases'],
                    'links': network_config['Links']
                }
                if network_config['IPAMConfig']:
                    new_network_config.update(
                        {
                            'ipv4_address': network_config['IPAddress'],
                            'ipv6_address': network_config['GlobalIPv6Address']
                        }
                    )
                try:
                    network.connect(**new_network_config)
                except docker.errors.APIError as e:
                    if any(err in str(e) for err in ['user configured subnets', 'user defined networks']):
                        if new_network_config.get('ipv4_address'):
                            del new_network_config['ipv4_address']
                        if new_network_config.get('ipv6_address'):
                            del new_network_config['ipv6_address']
                        network.connect(**new_network_config)
                    else:
                        logging.error('Unable to attach updated container to network "%s". Error: %s', network.name, e)

            new_container.start()

            logging.info(f'Successfully updated container {container.name}')
        else:
            logging.info(f'No new image found for container {container.name}')



@app.route('/webhooks/containers', methods=['POST'])
def main():
    if request.method == 'POST':
        try:
            importlib.reload(config)
        except Exception as e:
            logging.error(f'Could not reload config - {e}')
        if verify_signature(request, config.WEBHOOK_SECRET):
            recreate_containers(config.DOCKER_CONTAINERS)
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
    try:
        serve(app, host='0.0.0.0', port=8888)
    except Exception as e:
        logging.error(f'Could not create webhook server - {e}')
