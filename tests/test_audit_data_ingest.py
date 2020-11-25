from datetime import date

import boto3
import pytest

import audit_data_ingest

S3_PREFIX = "audit-data"
S3_PUBLISH_BUCKET = "target"
TODAY = "2020-10-10"
S3_OBJECT_FILENAME = "audit-data-1.json.enc"
SRC_DIR = "./data"
TMP_DIR = "tmp"

MOTO_SERVER_URL = "http://127.0.0.1:5000"


def test_hello(handle_server, monkeypatch):
    s3_client = boto3.client("s3", endpoint_url=MOTO_SERVER_URL)
    s3_client.create_bucket(Bucket=S3_PUBLISH_BUCKET)
    s3_object_key = f"{S3_PREFIX}/{today()}/{S3_OBJECT_FILENAME}"
    monkeypatch.setattr(audit_data_ingest, "get_client", mock_s3_client)
    monkeypatch.setattr(audit_data_ingest, "get_hsm_key", mock_get_hsm_key)
    audit_data_ingest.main(SRC_DIR, TMP_DIR, S3_PUBLISH_BUCKET, S3_PREFIX)
    assert len(s3_client.list_objects_v2(Bucket=S3_PUBLISH_BUCKET)['Contents']) == 2
    assert len(s3_client.get_object(Bucket=S3_PUBLISH_BUCKET, Key=s3_object_key)['Metadata']) == 3


def test_exception_when_decompression_fails(monkeypatch, handle_server):
    with pytest.raises(Exception):
        audit_data_ingest.main("unknow_dir", TMP_DIR, S3_PUBLISH_BUCKET, S3_PREFIX)


def today():
    return str(date.today())


def mock_get_hsm_key():
    return "keystest12345678"


def mock_s3_client(service_name):
    return boto3.client(service_name, endpoint_url=MOTO_SERVER_URL)
