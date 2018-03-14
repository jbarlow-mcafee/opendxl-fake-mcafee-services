from __future__ import absolute_import
from __future__ import print_function
import logging
import os
import sys
import time

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Event
from dxlbootstrap.util import MessageUtils

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

EVENT_TOPIC = "/mcafee/event/tie/file/detection"

config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

with DxlClient(config) as client:
    client.connect()
    event = Event(EVENT_TOPIC)
    payload = {
        "agentGuid": event.message_id,
        "detectionTime": int(time.time()),
        "hashes": [
            {"type": "md5",
             "value": "614rncUYF6CG17l+tSQQqw=="},
            {"type": "sha1",
             "value": "Q139Rw9ydDfHy08Hy6H5ofQnJlY="},
            {"type": "sha256",
             "value": "QUuxaxDs4tsthEjLnzE/gMt3wxDKDBnuA8c8ugwW/ts="}
        ],
        "localReputation": 1,
        "name": "FOCUS_MALWARE2.EXE",
        "remediationAction": 5
    }
    MessageUtils.dict_to_json_payload(event, payload)
    client.send_event(event)

print("Sent event")
