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

EVENT_TOPIC = "/mcafee/event/tie/file/firstinstance"

config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

with DxlClient(config) as client:
    client.connect()
    event = Event(EVENT_TOPIC)
    payload = {
        "agentGuid": event.message_id,
        "hashes": [
            {"type": "md5",
             "value": "MdvozEQ9LKf9I2rAClL7Fw=="},
            {"type": "sha1",
             "value": "LWykUGG3lyMS4A5ZM/3/lbuQths="},
            {"type": "sha256",
             "value": "qjxGHUwho5LjctDWykzrHk2ICY1YdllFTq9Nk8ZhiA8="}
        ],
        "name": "MORPH.EXE"
    }
    MessageUtils.dict_to_json_payload(event, payload)
    client.send_event(event)

print("Sent event")
