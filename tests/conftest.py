import os
import signal
import subprocess

import pytest

TESTING = 'testing'


@pytest.fixture(scope='session')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = TESTING
    os.environ['AWS_SECRET_ACCESS_KEY'] = TESTING
    os.environ['AWS_SECURITY_TOKEN'] = TESTING
    os.environ['AWS_SESSION_TOKEN'] = TESTING


@pytest.fixture(autouse=True, scope='session')
def handle_server():
    print("Starting Moto Server")
    process = subprocess.Popen("moto_server s3",
                               stdout=subprocess.PIPE,
                               shell=True,
                               preexec_fn=os.setsid)
    yield
    print("Stopping Moto Server")
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
