#!./venv/bin/python
#
# Author: jon4hz
# Date: 24.03.2021
# Desc: Webhook for cd
###################################################################################################

from hashlib import sha1
import hmac

from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/webhooks/containers', methods=['POST'])
def index():
    request_signature = request.headers.get('X-Hub-Signature')

    import config

    computed_signature = 'sha1' + hmac.new(config.WEBHOOK_SECRET,msg=request.data, digestmod=sha1)

    if not hmac.compare_digest(computed_signature.hexdigest(), request_signature):
        abort(500)