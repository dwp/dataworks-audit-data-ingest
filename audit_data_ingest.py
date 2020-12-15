import argparse
import datetime
import glob
import logging
import os
import shutil
import subprocess
import zlib
from base64 import b64encode, b64decode
from datetime import date
from os.path import join as pjoin, basename

import boto3
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

IV = "iv"
CIPHERTEXT = "ciphertext"
DATAKEYENCRYPTIONKEYID = "datakeyencryptionkeyid"
DATA_KEY = get_random_bytes(16)
NONCE = get_random_bytes(12)

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
logger = logging.getLogger("audit-log-exporter")


def filter_date(hdfsdir, start_date):
    datestr = hdfsdir.split("/")[-1]
    try:
        dirdate = datetime.datetime.strptime(datestr, "%Y-%m-%d")
    except ValueError:
        logger.warn(f"Skipping {hdfsdir} as it isn't a dated directory")
        return False
    return dirdate > start_date


def main(
    start_date,
    src_hdfs_dir,
    tmp_dir,
    s3_bucket,
    s3_prefix,
    hsm_key_id,
    aws_default_region,
    hsm_key_param_name,
):
    dates = get_auditlog_list(start_date)
    for day in dates:
        pass
    # copy_files_from_hdfs(day, tmp_dir)
    encrypt_and_upload_files(
        tmp_dir,
        s3_bucket,
        s3_prefix,
        hsm_key_id,
        aws_default_region,
        hsm_key_param_name,
    )

    # json_files = get_json_files(src_hdfs_dir)
    # encrypt_and_upload_json_files(json_files, tmp_dir, s3_bucket, s3_prefix)


def encrypt_and_upload_files(
    tmp_dir, s3_bucket, s3_prefix, hsm_key_id, aws_default_region, hsm_key_param_name
):
    hsm_key_file = b64decode(get_hsm_key(hsm_key_param_name))
    hsm_key = RSA.import_key(hsm_key_file)
    for root, dirs, files in os.walk(tmp_dir):
        for name in files:
            session_key = get_random_bytes(16)
            # Session key gets encrypted with RSA HSM public key
            cipher_rsa = PKCS1_OAEP.new(hsm_key)
            enc_session_key = cipher_rsa.encrypt(session_key)
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            # Data gets encrypted with AES session key (session_key)
            in_file = os.path.join(root, name)
            out_file = in_file + ".enc"
            with open(in_file, "rb") as fin, open(out_file, "wb") as fout:
                compressed_data = zlib.compress(fin.read())
                fout.write(cipher_aes.encrypt(compressed_data))
            # Metadata gets added to S3 object
            # data_key_nonce = get_random_bytes(12)
            # data_key = get_random_bytes(16)
            # data_key_cipher = AES.new(data_key, AES.MODE_GCM, data_key_nonce)
            # in_file = os.path.join(root, name)
            # out_file = in_file + ".enc"
            # with open(in_file, "rb") as fin, open(out_file, "wb") as fout:
            #     # Compress data before encrypting it
            #     compressed_data = zlib.compress(fin.read())
            #     fout.write(data_key_cipher.encrypt(compressed_data))
            # hsm_key_nonce = get_random_bytes(12)
            # hsm_key_cipher = AES.new(hsm_key, AES.MODE_GCM, hsm_key_nonce)
            # encrypted_data_key = hsm_key_cipher.encrypt(data_key)
            s3_object_metadata = {
                "x-amz-meta-iv": b64encode(cipher_aes.nonce),
                "x-amz-meta-ciphertext": b64encode(enc_session_key),
                "x-amz-meta-datakeyencryptionkeyid": hsm_key_id,
            }
            upload_to_s3(
                out_file, s3_object_metadata, s3_bucket, s3_prefix, aws_default_region
            )


def get_auditlog_list(start_date):
    logger.info("Finding all auditlogs to process")
    if start_date is not None:
        logger.info(f"Excluding entries older than {start_date}")
    try:
        process = subprocess.run(
            ["hdfs", "dfs", "-ls", "-C", "/etl/uc/auditlog"],
            check=True,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Couldn't list auditlog entries in HDFS: {e}")
        raise e
    # skip the last line of output as it's always blank
    alldates = process.stdout.split("\n")[0:-1]
    if start_date is None:
        dates = alldates
    else:
        dates = filter(lambda hdfsdir: filter_date(hdfsdir, start_date), alldates)
    return dates


def copy_files_from_hdfs(hdfs_dir, tmp_dir):
    logger.info(f"Retrieving {hdfs_dir} from HDFS")
    os.mkdir(tmp_dir)
    try:
        hdfs_dir = "/etl/uc/auditlog/2020-12-11"
        process = subprocess.run(
            ["hdfs", "dfs", "-copyToLocal", hdfs_dir, tmp_dir],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Couldn't copy files from HDFS: {e}")
        raise e


def today():
    return str(date.today())


def upload_to_s3(
    out_file, s3_object_metadata, s3_bucket, s3_prefix, aws_default_region
):
    # Upload files to S3
    encrypted_file_name = pjoin(tmp_dir, file)
    logger.info(f"Uploading {encrypted_file_name} to S3 ")
    s3_client = get_client("s3", aws_default_region)
    with open(encrypted_file_name, "rb") as data:
        s3_client.upload_fileobj(
            data,
            s3_bucket,
            f"{s3_prefix}/{today()}/{basename(file)}",
            ExtraArgs={"Metadata": s3_object_metadata},
        )


def get_client(service_name, aws_default_region):
    return boto3.client(service_name, region_name=aws_default_region)


def get_hsm_key(hsm_key_param_name):
    ssm_client = get_client("ssm", aws_default_region)
    return ssm_client.get_parameter(Name=hsm_key_param_name, WithDecryption=True)['Parameter']['Value']


def encrypt_and_upload_json_files(
    json_files, tmp_dir, s3_bucket, s3_prefix, hsm_key_param_name
):
    hsm_public_key = get_hsm_key(hsm_key_param_name)
    data_key_cipher = AES.new(hsm_public_key.encode(), AES.MODE_GCM, nonce=NONCE)
    # Encrypt data key using HSM public key
    data_key_ciphertext = data_key_cipher.encrypt(DATA_KEY)

    json_file_cipher = AES.new(DATA_KEY, AES.MODE_GCM, nonce=NONCE)
    logger.info("Creating tmp directory id it doesn't exist")

    # Add encrypted data key to S3 metadata dictionary
    s3_object_metadata = {
        IV: b64encode(NONCE).decode(),
        CIPHERTEXT: b64encode(data_key_ciphertext).decode(),
        DATAKEYENCRYPTIONKEYID: hsm_public_key,
    }

    # Create tmp directory if it doesn't exist
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    os.chmod(tmp_dir, 0o700)

    for json_file in json_files:
        encrypted_json_file_name = f"{basename(json_file)}.enc"
        with open(json_file, "rb") as fin, open(
            pjoin(tmp_dir, encrypted_json_file_name), "wb"
        ) as fout:
            # Compress data before encrypting it
            compressed_data = zlib.compress(fin.read())
            fout.write(json_file_cipher.encrypt(compressed_data))
        upload_to_s3(
            tmp_dir, encrypted_json_file_name, s3_object_metadata, s3_bucket, s3_prefix
        )


def clean_dir(tmp_dir):
    pass
    # if os.path.exists(tmp_dir):
    #    logger.info("CLeaning temp_dir")
    #    shutil.rmtree(tmp_dir)


def find_start_date():
    progress_file = "/home/aws-audit/audit-data-export-progress.log"
    try:
        with open(progress_file, "r") as f:
            start_datestr = f.read().strip("\n")
            start_date = datetime.datetime.strptime(start_datestr, "%Y-%m-%d")
    except ValueError:
        logger.error(
            f"Couldn't parse date in {progress_file}, it should be in %Y-%m-%d format"
        )
        raise ValueError
    except IOError:
        logger.warn(f"No progress file found at {progress_file}; processing all dates")

    return start_date


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Copy UC audit data to S3")

    parser.add_argument("--src-hdfs-dir", required=True, help="HDFS Source Directory")
    parser.add_argument(
        "--s3-publish-bucket",
        required=True,
        help="S3 bucket to copy the processed data to",
    )
    parser.add_argument(
        "--s3-prefix", required=True, help="S3 prefix to copy the processed data to"
    )
    parser.add_argument(
        "--tmp",
        required=False,
        default="/data/auditlogs/tmp",
        help="Local Temporary Directory",
    )
    parser.add_argument(
        "--hsm-key-id",
        required=True,
        help="HSM Key ID in 'cloudhsm:privkeyid:pubkeyid' format",
    )
    parser.add_argument(
        "--hsm-key-param-name", required=True, help="HSM Public Key SSM Parameter name"
    )
    parser.add_argument(
        "--aws-default-region",
        required=False,
        default="eu-west-2",
        help="The Default AWS Region this script will be ran in",
    )

    args = parser.parse_args()
    tmp_dir = args.tmp
    src_hdfs_dir = args.src_hdfs_dir
    s3_bucket = args.s3_publish_bucket
    s3_prefix = args.s3_prefix
    hsm_key_id = args.hsm_key_id
    hsm_key_param_name = args.hsm_key_param_name
    aws_default_region = args.aws_default_region

    try:
        clean_dir(tmp_dir)
        start_date = find_start_date()
        main(
            start_date,
            src_hdfs_dir,
            tmp_dir,
            s3_bucket,
            s3_prefix,
            hsm_key_id,
            aws_default_region,
            hsm_key_param_name,
        )
    except Exception as ex:
        logger.error("Error processing files")
        raise ex
    finally:
        clean_dir(tmp_dir)
