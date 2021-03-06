# Base image from Python 2.7 (slim)
FROM python:2.7-slim

VOLUME ["/opt/dxlfakemcafeeservices-config"]

# Install required packages
RUN pip install "dxlbootstrap>=0.1.3" "dxlclient"

# Copy application files
COPY . /tmp/build
WORKDIR /tmp/build

# Clean application
RUN python ./clean.py

# Build application
RUN python ./setup.py bdist_wheel

# Install application
RUN pip install dist/*.whl

# Cleanup build
RUN rm -rf /tmp/build

################### INSTALLATION END #######################
#
# Run the application.
#
# NOTE: The configuration files for the application must be
#       mapped to the path: /opt/dxlfakemcafeeservices-config
#
# For example, specify a "-v" argument to the run command
# to mount a directory on the host as a data volume:
#
#   -v /host/dir/to/config:/opt/dxlfakemcafeeservices-config
#
CMD ["python", "-m", "dxlfakemcafeeservices", "/opt/dxlfakemcafeeservices-config"]
