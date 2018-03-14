import logging

from dxlbootstrap.app import Application
from dxlclient.service import ServiceRegistrationInfo
from requesthandlers import *


# Configure local logger
logger = logging.getLogger(__name__)


class FakeMcAfeeServices(Application):
    """
    The "OpenDXL Fake McAfee Services" application class.
    """

    def __init__(self, config_dir):
        """
        Constructor parameters:

        :param config_dir: The location of the configuration files for the
            application
        """
        super(FakeMcAfeeServices, self).__init__(config_dir, "dxlfakemcafeeservices.config")

    @property
    def client(self):
        """
        The DXL client used by the application to communicate with the DXL
        fabric
        """
        return self._dxl_client


    @property
    def config(self):
        """
        The application configuration (as read from the "dxlfakemcafeeservices.config" file)
        """
        return self._config

    def on_run(self):
        """
        Invoked when the application has started running.
        """
        logger.info("On 'run' callback.")

    def on_load_configuration(self, config):
        """
        Invoked after the application-specific configuration has been loaded

        This callback provides the opportunity for the application to parse
        additional configuration properties.

        :param config: The application configuration
        """
        logger.info("On 'load configuration' callback.")

    def on_dxl_connect(self):
        """
        Invoked after the client associated with the application has connected
        to the DXL fabric.
        """
        logger.info("On 'DXL connect' callback.")
    
    def on_register_services(self):
        """
        Invoked when services should be registered with the application
        """
        # Register service 'fake_mcafee_service'
        logger.info("Registering service: {0}".format("fake_mcafee_service"))
        service = ServiceRegistrationInfo(self._dxl_client, "/fake/mcafee/services")
        logger.info("Registering request callback: {0}".format("fake_mar_api_search"))
        self.add_request_callback(service, "/mcafee/mar/service/api/search",
                                  FakeMarApiSearchRequestCallback(self), True)
        logger.info("Registering request callback: {0}".format("fake_tie_file_reputation"))
        tie_reputation_callback = FakeTieReputationCallback(self)
        for tie_topic in [FakeTieReputationCallback.TIE_GET_FILE_REPUTATION_TOPIC,
                          FakeTieReputationCallback.TIE_SET_FILE_REPUTATION_TOPIC,
                          FakeTieReputationCallback.TIE_GET_CERT_REPUTATION_TOPIC]:
            self.add_request_callback(service, tie_topic, tie_reputation_callback, True)
        self.register_service(service)
