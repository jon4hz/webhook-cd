#!./venv/bin/python
#
# Author: jon4hz
# Date: 24.03.2021
# Desc: Webhook for cd
###################################################################################################

from hashlib import sha1
import hmac

from flask import Flask, request

app = Flask(__name__)

def verify_signature(req):
    received_sign = req.headers.get('X-Hub-Signature').split('sha1=')[-1].strip()
    secret = 'my_secret_string'.encode()
    expected_sign = hmac.HMAC(key=secret, msg=req.data, digestmod=sha1).hexdigest()
    return hmac.compare_digest(received_sign, expected_sign)


@app.route('/webhooks/containers', methods=['POST'])
def main():
    if request.method == 'POST':
        if verify_signature(request):
            import config
            print(config.DOCKER_CONTAINERS)
            return 'Success', 200
        return 'Forbidden', 403
    return 'Not allowed', 405