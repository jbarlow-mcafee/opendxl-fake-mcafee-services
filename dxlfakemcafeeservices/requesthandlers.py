import copy
import logging
import re
import time
import uuid

from dxlclient.callbacks import RequestCallback
from dxlclient.message import Event, Response, ErrorResponse
from dxlbootstrap.util import MessageUtils

# Configure local logger
logger = logging.getLogger(__name__)

def _make_output_item(output):
    return {"count": 1,
            "created_at": time.strftime('%Y-%M-%dT%H:%M:%SZ'),
            "id": "{1=[" + str(output) + "]}",
            "output": output}

def _make_output_items(output_id, output_values):
    return [_make_output_item({output_id: output_value})
            for output_value in output_values]


class FakeMarApiSearchRequestCallback(RequestCallback):
    """
    'fake_mar_api_search' request handler registered with topic
    '/mcafee/mar/service/api/search'
    """

    IP_ADDRESS_ID = "ipaddrid"
    PROCESSES_ID = "processesid"

    RESULTS = {IP_ADDRESS_ID: _make_output_items("HostInfo|ip_address",
                                                 ["192.168.130.152",
                                                  "192.168.130.133"]),
               PROCESSES_ID: _make_output_items("Processes|name",
                                                ["MARService.exe",
                                                 "OneDrive.exe",
                                                 "RuntimeBroker.exe",
                                                 "SearchIndexer.exe",
                                                 "SearchUI.exe",
                                                 "ShellExperienceHost.exe",
                                                 "SkypeHost.exe",
                                                 "System",
                                                 "UpdaterUI.exe",
                                                 "VGAuthService.exe",
                                                 "WUDFHost.exe",
                                                 "WmiApSrv.exe",
                                                 "WmiPrvSE.exe",
                                                 "WmiPrvSE.exe",
                                                 "[System Process]"])}

    PROJECTION_TO_ID = {
        "HostInfo|ip_address": IP_ADDRESS_ID,
        "Processes": PROCESSES_ID
    }

    SEARCHES = {}

    def __init__(self, app, status_checks_until_finished=0):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        """
        super(FakeMarApiSearchRequestCallback, self).__init__()
        self._app = app
        self._status_checks_until_finished = status_checks_until_finished

    @staticmethod
    def _make_error_response(code, message):
        return {"code": code,
                "body": {
                    "applicationErrorList": [
                        {"code": code,
                         "message": message}
                    ]
                }}

    @staticmethod
    def _get_projection_as_string(projections):
        result = ""
        for projection in projections:
            result += projection["name"]
            if "outputs" in projection:
                result += "|"
                result += "|".join(
                    [output for output in projection["outputs"]])
        return result

    def on_request(self, request):
        """
        Invoked when a request message is received.

        :param request: The request message
        """
        request_payload = MessageUtils.json_payload_to_dict(request)
        logger.info(
            "Request received on topic: '{0}' with payload: '{1}'".format(
                request.destination_topic, request_payload))

        try:
            res = Response(request)

            payload = {"code": 200,
                       "body": {}}

            if request_payload["target"] == "/v1/simple":
                if request_payload["method"] != 'POST':
                    payload = self._make_error_response(
                        405, "Unsupported method")
                elif "body" not in request_payload or \
                    "projections" not in request_payload["body"]:
                    payload = self._make_error_response(
                        400, "Missing body or projections parameter")
                else:
                    projections_as_str = self._get_projection_as_string(
                        request_payload["body"]["projections"])
                    if projections_as_str in self.PROJECTION_TO_ID:
                        search_id = str(uuid.uuid4()).replace("-", "")[:24]
                        self.SEARCHES[search_id] = {
                            "statusChecksUntilFinished": \
                                self._status_checks_until_finished,
                            "projectionId": self.PROJECTION_TO_ID[
                                projections_as_str]
                        }
                        payload["body"]["id"] = search_id
                    else:
                        payload = self._make_error_response(
                            501, "Unsupported projection")
            else:
                search_id_match = re.match(r".*/v1/(\w+)/.*",
                                      request_payload["target"])
                if search_id_match and search_id_match.group(1) in self.SEARCHES:
                    search_entry = self.SEARCHES[search_id_match.group(1)]
                    request_items = self.RESULTS[search_entry["projectionId"]]
                    if request_payload["target"].endswith("/status"):
                        if request_payload["method"] != 'GET':
                            payload = self._make_error_response(
                                405, "Unsupported method")
                        elif search_entry["statusChecksUntilFinished"]:
                            search_entry["statusChecksUntilFinished"] -= 1
                            payload["body"]["status"] = "RUNNING"
                        else:
                            payload["body"]["results"] = len(request_items)
                            payload["body"]["errors"] = 0
                            payload["body"]["hosts"] = 1
                            payload["body"]["subscribedHosts"] = 1
                            payload["body"]["status"] = "FINISHED"
                    elif request_payload["target"].endswith("/results"):
                        if request_payload["method"] != 'GET':
                            payload = self._make_error_response(
                                405, "Unsupported method")
                        elif "parameters" in request_payload and \
                            "$offset" in request_payload["parameters"] and \
                            "$limit" in request_payload["parameters"]:
                            offset = request_payload["parameters"]["$offset"]
                            limit = request_payload["parameters"]["$limit"]
                            payload["body"]["items"] = request_items[
                                offset:
                                offset + limit
                            ]
                        else:
                            payload["body"]["items"] = request_items
                else:
                    payload = self._make_error_response(
                        404, "Id not found")

            MessageUtils.dict_to_json_payload(res, payload)
            self._app.client.send_response(res)

        except Exception as ex:
            logger.exception("Error handling request")
            err_res = ErrorResponse(request, error_code=0,
                                    error_message=MessageUtils.encode(str(ex)))
            self._app.client.send_response(err_res)


class FakeTieReputationCallback(RequestCallback):
    """
    'fake_tie_file_reputation' request handler registered with topic
    '/mcafee/service/tie/file/reputation'
    """

    TIE_GET_AGENTS_FOR_FILE_TOPIC = "/mcafee/service/tie/file/agents"
    TIE_GET_FILE_REPUTATION_TOPIC = "/mcafee/service/tie/file/reputation"
    TIE_SET_FILE_REPUTATION_TOPIC = "/mcafee/service/tie/file/reputation/set"
    TIE_GET_CERT_REPUTATION_TOPIC = "/mcafee/service/tie/cert/reputation"

    FILE_REPUTATION_CHANGE_TOPIC = "/mcafee/event/tie/file/repchange/broadcast"

    REPUTATION_METADATA = {
        "notepad.exe": {
            "agents": [
                {
                    "agentGuid": "{3a6f574a-3e6f-436d-acd4-bcde336b054d}",
                    "date": 1475873692
                },
                {
                    "agentGuid": "{d48d3d1a-915e-11e6-323a-000c2992f5d9}",
                    "date": 1476316674
                },
                {
                    "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
                    "date": 1478626172
                }
            ],
            "hashes": {
                "md5": "8se7isyX+S6Yei1Ah9AhsQ==",
                "sha1": "frATnSF1c5s8yw0REAZ4IL5qvSk=",
                "sha256": "FC4daI7wVoNww3GH/Z8jUdfd7aV0+L+psPpO9C24WqI="
            },
            "reputations": [
                {
                    "attributes": {
                        "2120340": "2139160704"
                    },
                    "createDate": 1451502875,
                    "providerId": 1,
                    "trustLevel": 99
                },
                {
                    "attributes": {
                        "2101652": "17",
                        "2102165": "1451502875",
                        "2111893": "21",
                        "2114965": "0",
                        "2139285": "72339069014638857"
                    },
                    "createDate": 1451502875,
                    "providerId": 3,
                    "trustLevel": 0
                }
            ],
            "relationships": {
                "certificate": {
                    "hashes": [
                        {"type": "md5",
                         "value": "MdvozEQ9LKf9I2rAClL7Fw=="},
                        {"type": "sha1",
                         "value": "LWykUGG3lyMS4A5ZM/3/lbuQths="},
                        {"type": "sha256",
                         "value": "qjxGHUwho5LjctDWykzrHk2ICY1YdllFTq9Nk8ZhiA8="}
                    ],
                    "publicKeySha1": "Q139Rw9ydDfHy08Hy6H5ofQnJlY="
                }
            }
        },
        "EICAR": {
            "hashes": {
                "md5": "RNiGEv6oqPNt6C4SeKuwLw==",
                "sha1": "M5WFbOgfK3OC3ucmAveYtkLxQUA=",
                "sha256": "J1oCG7+2SJ5U1HGJn3250WY/xpXsL+KixFOKq/ZR/Q8="
            },
            "reputations": [
                {
                    "attributes": {
                        "2120340": "2139162632"
                    },
                    "createDate": 1451504331,
                    "providerId": 1,
                    "trustLevel": 1
                },
                {
                    "attributes": {
                        "2101652": "11",
                        "2102165": "1451504331",
                        "2111893": "22",
                        "2114965": "0",
                        "2139285": "72339069014638857"
                    },
                    "createDate": 1451504331,
                    "providerId": 3,
                    "trustLevel": 0
                }
            ]
        },
        "cert1": {
            "hashes": {
                "sha1": "bq4m24wTGCp5R5gpkbQyFzLMPeI=",
                "publicKeySha1": "O4ei1vOXcBYDZLeaFS/Mc7riet8="
            },
            "reputations": [
                {
                    "attributes": {
                        "2108821": "94",
                        "2109077": "1454912619",
                        "2117524": "0",
                        "2120596": "0"
                    },
                    "createDate": 1476318514,
                    "providerId": 2,
                    "trustLevel": 99
                },
                {
                    "attributes": {
                        "2109333": "12",
                        "2109589": "1476318514",
                        "2139285": "73183493944770750"
                    },
                    "createDate": 1476318514,
                    "providerId": 4,
                    "trustLevel": 0
                }
            ]
        }
    }

    def _set_hash_algos_for_item(self, item_name, hashes):
        for hash_type, hash_value in hashes.items():
            if hash_type not in self.hash_algos_to_files:
                self.hash_algos_to_files[hash_type] = {}
            self.hash_algos_to_files[hash_type][hash_value] = item_name

    def __init__(self, app):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        """
        super(FakeTieReputationCallback, self).__init__()

        self.hash_algos_to_files = {}

        for file_name, reputation in self.REPUTATION_METADATA.items():
            self._set_hash_algos_for_item(file_name, reputation["hashes"])

        self._app = app
        self._callbacks = {
            self.TIE_GET_AGENTS_FOR_FILE_TOPIC: self._get_agents_for_file,
            self.TIE_GET_FILE_REPUTATION_TOPIC: self._get_reputation,
            self.TIE_SET_FILE_REPUTATION_TOPIC: self._set_file_reputation,
            self.TIE_GET_CERT_REPUTATION_TOPIC: self._get_cert_reputation
        }

    def on_request(self, request):
        """
        Invoked when a request message is received.

        :param request: The request message
        """
        # Handle request
        request_payload = MessageUtils.json_payload_to_dict(request)
        logger.info(
            "Request received on topic: '{0}' with payload: '{1}'".format(
                request.destination_topic, request_payload))
        if request.destination_topic in self._callbacks:
            try:
                self._callbacks[request.destination_topic](request,
                                                           request_payload)
            except Exception as ex:
                logger.exception("Error handling request")
                err_res = ErrorResponse(request, error_code=0,
                                        error_message=MessageUtils.encode(
                                            str(ex)))
                self._app.client.send_response(err_res)
        else:
            logger.exception("Unknown topic: %s", request.destination_topic)
            err_res = ErrorResponse(
                request,
                error_code=0,
                error_message=MessageUtils.encode(
                    "Unknown topic: " + request.destination_topic))
            self._app.client.send_response(err_res)

    def _set_file_reputation(self, request, request_payload):
        self._set_item_reputation(request, request_payload,
                                  request_payload["filename"],
                                  self.FILE_REPUTATION_CHANGE_TOPIC)

    def _set_item_reputation(self, request, request_payload,
                             item_name, change_topic):
        new_entry = None

        if item_name in self.REPUTATION_METADATA:
            new_reputations = self.REPUTATION_METADATA[item_name]["reputations"]
            for reputation_entry in new_reputations:
                if reputation_entry["providerId"] == request_payload["providerId"]:
                    new_entry = reputation_entry
        else:
            new_reputations = []
            self.REPUTATION_METADATA[item_name] = {
                "hashes": {}, "reputations": new_reputations}
        old_reputations = copy.deepcopy(new_reputations)

        old_hashes = self.REPUTATION_METADATA[item_name]["hashes"]
        for hash_type, hash_value in old_hashes.items():
            if hash_type in self.hash_algos_to_files and \
                hash_value in self.hash_algos_to_files[hash_type]:
                del self.hash_algos_to_files[hash_type][hash_value]

        new_hashes = {new_hash["type"]: new_hash["value"] \
                      for new_hash in request_payload["hashes"]}
        self._set_hash_algos_for_item(item_name, new_hashes)
        self.REPUTATION_METADATA[item_name]["hashes"] = new_hashes

        if not new_entry:
            new_entry = {"attributes": {},
                         "providerId": request_payload["providerId"]}
        new_entry["trustLevel"] = request_payload["trustLevel"]
        new_entry["createDate"] = int(time.time())
        new_reputations.append(new_entry)

        self._app.client.send_response(Response(request))

        event = Event(change_topic)
        event_payload = {
            "hashes": request_payload["hashes"],
            "oldReputations": {"reputations": old_reputations},
            "newReputations": {"reputations": new_reputations},
            "updateTime": int(time.time())
        }
        if "relationships" in self.REPUTATION_METADATA[item_name]:
            event_payload["relationships"] = self.REPUTATION_METADATA[item_name]["relationships"]

        MessageUtils.dict_to_json_payload(event, event_payload)
        self._app.client.send_event(event)

    def _get_cert_reputation(self, request, request_payload):
        if "publicKeySha1" in request_payload:
            request_payload["hashes"].append({
                "type": "publicKeySha1",
                "value": request_payload["publicKeySha1"]
            })
            self._get_reputation(request, request_payload)

    def _get_reputation_for_hashes(self, hashes):
        hash_match_result = None
        for hash_item in hashes:
            hash_match_current = None
            hash_type = hash_item["type"]
            if hash_item["type"] in self.hash_algos_to_files:
                hash_value = hash_item["value"]
                if hash_item["value"] in self.hash_algos_to_files[hash_type]:
                    hash_match_current = \
                        self.hash_algos_to_files[hash_type][hash_value]
            if not hash_match_current:
                hash_match_result = None
                break
            if hash_match_result is None:
                hash_match_result = hash_match_current
            elif hash_match_current != hash_match_result:
                hash_match_result = None
                break

        if not hash_match_result:
            raise Exception("Could not find reputation")
        logger.info("Reputation requested for '{0}'".format(
            hash_match_result))
        return hash_match_result

    def _get_agents_for_file(self, request, request_payload):
        hash_match_result = self._get_reputation_for_hashes(
            request_payload["hashes"])
        metadata = self.REPUTATION_METADATA[hash_match_result]

        res = Response(request)
        payload = {"agents": metadata["agents"]} if "agents" in metadata else {}
        MessageUtils.dict_to_json_payload(res, payload)
        self._app.client.send_response(res)

    def _get_reputation(self, request, request_payload):
        hash_match_result = self._get_reputation_for_hashes(
            request_payload["hashes"])

        res = Response(request)

        payload = {
            "props": {
                "serverTime": int(time.time()),
                "submitMetaData": 1
            },
            "reputations": self.REPUTATION_METADATA[
                hash_match_result]["reputations"],
        }

        MessageUtils.dict_to_json_payload(res, payload)
        self._app.client.send_response(res)
