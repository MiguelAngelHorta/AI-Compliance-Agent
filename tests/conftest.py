"""Shared test fixtures."""

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def aws_session():
    """Create a mocked AWS session for testing."""
    with mock_aws():
        session = boto3.Session(
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        yield session
