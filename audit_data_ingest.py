import argparse
import glob
import logging
import os
import shutil
import zlib
from base64 import b64encode
from datetime import date
from os.path import join as pjoin, basename

import boto3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

IV = "iv"
CIPHERTEXT = "ciphertext"
DATAKEYENCRYPTIONKEYID = "datakeyencryptionkeyid"
DATA_KEY = get_random_bytes(16)
NONCE = get_random_bytes(12)

logger = logging.getLogger(__name__)


def main(src_dir, tmp_dir, s3_bucket, s3_prefix):
    json_files = get_json_files(src_dir)
    encrypt_and_upload_json_files(json_files, tmp_dir, s3_bucket, s3_prefix)


def today():
    return str(date.today())


def upload_to_s3(tmp_dir, file, s3_object_metadata, s3_bucket, s3_prefix):
    # Upload files to S3
    encrypted_file_name = pjoin(tmp_dir, file)
    logger.info(f"Uploading {encrypted_file_name} to S3 ")
    s3_client = get_client("s3")
    with open(encrypted_file_name, "rb") as data:
        s3_client.upload_fileobj(
            data,
            s3_bucket,
            f"{s3_prefix}/{today()}/{basename(file)}",
            ExtraArgs={"Metadata": s3_object_metadata}
        )


def get_client(service_name):
    return boto3.client(service_name)


def get_hsm_key():
    ssm_client = get_client("ssm")
    return ssm_client.get_parameter(Name="ucfs.development.businessdata.hsmkey.pub")


def encrypt_and_upload_json_files(json_files, tmp_dir, s3_bucket, s3_prefix):
    hsm_public_key = get_hsm_key()
    data_key_cipher = AES.new(hsm_public_key.encode(), AES.MODE_GCM, nonce=NONCE)
    # Encrypt data key using HSM public key
    data_key_ciphertext = data_key_cipher.encrypt(DATA_KEY)

    json_file_cipher = AES.new(DATA_KEY, AES.MODE_GCM, nonce=NONCE)
    logger.info("Creating tmp directory id it doesn't exist")

    # Add encrypted data key to S3 metadata dictionary
    s3_object_metadata = {IV: b64encode(NONCE).decode(),
                          CIPHERTEXT: b64encode(data_key_ciphertext).decode(),
                          DATAKEYENCRYPTIONKEYID: hsm_public_key}

    # Create tmp directory if it doesn't exist
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    os.chmod(tmp_dir, 0o700)

    for json_file in json_files:
        encrypted_json_file_name = f"{basename(json_file)}.enc"
        with open(json_file, "rb") as fin, open(pjoin(tmp_dir, encrypted_json_file_name), "wb") as fout:
            # Compress data before encrypting it
            compressed_data = zlib.compress(fin.read())
            fout.write(json_file_cipher.encrypt(compressed_data))
        upload_to_s3(tmp_dir, encrypted_json_file_name, s3_object_metadata, s3_bucket, s3_prefix)


def get_json_files(src_dir):
    logger.info("Searching source directory for JSON files")
    json_files = glob.glob(pjoin(src_dir, "*.json"))
    try:
        os.stat(json_files[0])
        logger.info(f"Found {len(json_files)} JSON files")
    except BaseException as ex:
        logger.error("No JSON files found in source directory")
        raise ex
    return json_files


def clean_dir(tmp_dir):
    if os.path.exists(tmp_dir):
        logger.info("CLeaning temp_dir")
        shutil.rmtree(tmp_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Copy UC audit data to S3")

    parser.add_argument(
        "-s",
        "--src",
        required=True,
        help="Local Source Directory",
    )
    parser.add_argument(
        "-s3b",
        "--s3_publish_bucket",
        required=True,
        help="S3 bucket to copy the processed data to",
    )
    parser.add_argument(
        "-s3p",
        "--s3_prefix",
        required=True,
        help="S3 prefix to copy the processed data to",
    )
    parser.add_argument(
        "-t",
        "--tmp",
        required=False,
        default="./tmp/",
        help="Local Temporary Directory",
    )

    args = parser.parse_args()
    tmp_dir = args.tmp
    src_dir = args.src
    s3_bucket = args.s3_publish_bucket
    s3_prefix = args.s3_prefix

    try:
        clean_dir(tmp_dir)
        main(src_dir, tmp_dir, s3_bucket, s3_prefix)
    except Exception as ex:
        logger.error("Error processing files")
        raise ex
    finally:
        clean_dir(tmp_dir)
