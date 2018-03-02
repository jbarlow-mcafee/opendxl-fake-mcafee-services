import logging
import time

from dxlclient.callbacks import RequestCallback
from dxlclient.message import Response, ErrorResponse
from dxlbootstrap.util import MessageUtils


# Configure local logger
logger = logging.getLogger(__name__)


class FakeMarApiSearchRequestCallback(RequestCallback):
    """
    'fake_mar_api_search' request handler registered with topic
    '/mcafee/mar/service/api/search'
    """

    FAKE_SEARCH_ID = "fakeid"

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
                       "body": {
                           "id": self.FAKE_SEARCH_ID,
                           "status": "FINISHED",
                           "items": [
                               {
                                   "count": 1,
                                   "created_at": "2016-09-19T18:03:07.722Z",
                                   "id": "{1=[10.84.200.99]}",
                                   "output": {
                                       "HostInfo|ip_address": "10.84.200.99"
                                   }
                               }
                           ]

                       },
                       }

            if request_payload["target"] == "/v1/simple":
                if request_payload["method"] != 'POST':
                    payload = self._make_error_response(
                        405, "Unsupported method")
                elif "body" not in request_payload or \
                    "projections" not in request_payload["body"] or \
                    request_payload["body"]["projections"] != \
                        [{"name": "HostInfo", "outputs": ["ip_address"]}]:
                    payload = self._make_error_response(
                        501, "Unsupported projection")
            elif not request_payload["target"].startswith(
                            "/v1/" + self.FAKE_SEARCH_ID + "/"):
                payload = self._make_error_response(
                    404, "Unknown search id")
            elif request_payload["target"].endswith("/results"):
                if request_payload["method"] != 'GET':
                    payload = self._make_error_response(
                        405, "Unsupported method")
                elif request_payload["parameters"] != {
                    "$offset": 0,
                    "$limit": 10,
                    "filter": "",
                    "sortBy": "count",
                    "sortDirection": "desc"
                }:
                    payload = self._make_error_response(
                        501, "Unsupported parameters")

            # Set payload
            MessageUtils.dict_to_json_payload(res, payload)

            # Send response
            self._app.client.send_response(res)

        except Exception as ex:
            logger.exception("Error handling request")
            err_res = ErrorResponse(request, error_code=0,
                                    error_message=MessageUtils.encode(str(ex)))
            self._app.client.send_response(err_res)


class FakeTieFileReputationRequestCallback(RequestCallback):
    """
    'fake_tie_file_reputation' request handler registered with topic
    '/mcafee/service/tie/file/reputation'
    """

    HASHES = {
        "md5": {
            "8se7isyX+S6Yei1Ah9AhsQ==": "notepad.exe",
            "RNiGEv6oqPNt6C4SeKuwLw==": "EICAR"
        },
        "sha1": {
            "frATnSF1c5s8yw0REAZ4IL5qvSk=": "notepad.exe",
            "M5WFbOgfK3OC3ucmAveYtkLxQUA=": "EICAR"
        }
    }

    REPUTATIONS = {
        "notepad.exe": [
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
        "EICAR": [
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

    def __init__(self, app):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        """
        super(FakeTieFileReputationRequestCallback, self).__init__()

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

        try:
            hash_match_result = None
            for hash_item in request_payload["hashes"]:
                hash_match_current = None
                hash_type = hash_item["type"]
                if hash_item["type"] in self.HASHES:
                    hash_value = hash_item["value"]
                    if hash_item["value"] in self.HASHES[hash_type]:
                        hash_match_current = self.HASHES[hash_type][hash_value]
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

            payload = {"props": {
                "serverTime": int(time.time()),
                "submitMetaData": 1
            },
                "reputations": self.REPUTATIONS[hash_match_result],
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
