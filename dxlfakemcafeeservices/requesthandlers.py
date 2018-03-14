import copy
import logging
import re
import time

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

    def __init__(self, app):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        """
        super(FakeMarApiSearchRequestCallback, self).__init__()
        self._app = app

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
        # Handle request
        request_payload = MessageUtils.json_payload_to_dict(request)
        logger.info(
            "Request received on topic: '{0}' with payload: '{1}'".format(
                request.destination_topic, request_payload))

        try:
            # Create response
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
                        payload["body"]["id"] = self.PROJECTION_TO_ID[
                            projections_as_str]
                    else:
                        payload = self._make_error_response(
                            501, "Unsupported projection")
            else:
                request_id = re.match(r".*/v1/(\w+)/.*",
                                      request_payload["target"])
                if request_id and request_id.group(1) in self.RESULTS:
                    request_items = self.RESULTS[request_id.group(1)]
                    if request_payload["target"].endswith("/status"):
                        if request_payload["method"] != 'GET':
                            payload = self._make_error_response(
                                405, "Unsupported method")
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

            # Set payload
            MessageUtils.dict_to_json_payload(res, payload)

            # Send response
            self._app.client.send_response(res)

        except Exception as ex:
            logger.exception("Error handling request")
            err_res = ErrorResponse(request, error_code=0,
                                    error_message=MessageUtils.encode(str(ex)))
            self._app.client.send_response(err_res)


class FakeTieFileReputationCallback(RequestCallback):
    """
    'fake_tie_file_reputation' request handler registered with topic
    '/mcafee/service/tie/file/reputation'
    """

    FILE_REPUTATION_CHANGE_TOPIC = "/mcafee/event/tie/file/repchange/broadcast"

    FILE_METADATA = {
        "notepad.exe": {
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
            ]
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
        }
    }

    def _set_hash_algos_for_file(self, file_name, hashes):
        for hash_type, hash_value in hashes.items():
            if hash_type not in self.hash_algos_to_files:
                self.hash_algos_to_files[hash_type] = {}
            self.hash_algos_to_files[hash_type][hash_value] = file_name

    def __init__(self, app):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        """
        super(FakeTieFileReputationCallback, self).__init__()

        self.hash_algos_to_files = {}

        for file_name, reputation in self.FILE_METADATA.items():
            self._set_hash_algos_for_file(file_name, reputation["hashes"])

        self._app = app

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
        if request.destination_topic.endswith("set"):
            self.on_set_request(request, request_payload)
        else:
            self.on_get_request(request, request_payload)

    def on_set_request(self, request, request_payload):
        request_payload = MessageUtils.json_payload_to_dict(request)
        file_name = request_payload["filename"]
        new_entry = None

        if file_name in self.FILE_METADATA:
            new_reputations = self.FILE_METADATA[file_name]["reputations"]
            for reputation_entry in new_reputations:
                if reputation_entry["providerId"] == request_payload["providerId"]:
                    new_entry = reputation_entry
        else:
            new_reputations = []
            self.FILE_METADATA[file_name] = {"hashes": {},
                                             "reputations": new_reputations}
        old_reputations = copy.deepcopy(new_reputations)

        old_hashes = self.FILE_METADATA[file_name]["hashes"]
        for hash_type, hash_value in old_hashes.items():
            if hash_type in self.hash_algos_to_files and \
                hash_value in self.hash_algos_to_files[hash_type]:
                del self.hash_algos_to_files[hash_type][hash_value]

        new_hashes = {new_hash["type"]: new_hash["value"] \
                      for new_hash in request_payload["hashes"]}
        self._set_hash_algos_for_file(file_name, new_hashes)
        self.FILE_METADATA[file_name]["hashes"] = new_hashes

        if not new_entry:
            new_entry = {"attributes": {},
                         "providerId": request_payload["providerId"]}
        new_entry["trustLevel"] = request_payload["trustLevel"]
        new_entry["createDate"] = int(time.time())
        new_reputations.append(new_entry)

        self._app.client.send_response(Response(request))

        event = Event(self.FILE_REPUTATION_CHANGE_TOPIC)
        event_payload = {
            "hashes": request_payload["hashes"],
            "oldReputations": {"reputations": old_reputations},
            "newReputations": {"reputations": new_reputations},
            "updateTime": int(time.time())
        }

        MessageUtils.dict_to_json_payload(event, event_payload)
        self._app.client.send_event(event)

    def on_get_request(self, request, request_payload):
        try:
            hash_match_result = None
            for hash_item in request_payload["hashes"]:
                hash_match_current = None
                hash_type = hash_item["type"]
                if hash_item["type"] in self.hash_algos_to_files:
                    hash_value = hash_item["value"]
                    if hash_item["value"] in self.hash_algos_to_files[hash_type]:
                        hash_match_current = self.hash_algos_to_files[hash_type][hash_value]
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

            # Create response
            res = Response(request)

            payload = {
                "props": {
                    "serverTime": int(time.time()),
                    "submitMetaData": 1
                },
                "reputations": self.FILE_METADATA[
                    hash_match_result]["reputations"],
            }

            # Set payload
            MessageUtils.dict_to_json_payload(res, payload)

            # Send response
            self._app.client.send_response(res)

        except Exception as ex:
            logger.exception("Error handling request")
            err_res = ErrorResponse(request, error_code=0,
                                    error_message=MessageUtils.encode(str(ex)))
            self._app.client.send_response(err_res)
