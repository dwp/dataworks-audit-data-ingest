"""
Copy files from HDFS, encrypt them and upload them to S3.
"""
import argparse
import datetime
import logging
import os
import shutil
import subprocess
import zlib
from base64 import b64encode, b64decode
from concurrent.futures import ProcessPoolExecutor, wait, ThreadPoolExecutor

import boto3
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from botocore.exceptions import ClientError

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
logger = logging.getLogger("audit-log-exporter")


def filter_date(hdfsdir, start_date):
    datestr = hdfsdir.split("/")[-1]
    try:
        dirdate = datetime.datetime.strptime(datestr, "%Y-%m-%d")
    except ValueError:
        logger.warning("Skipping %s as it isn't a dated directory", hdfsdir)
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
        progress_file,
        processes
):
    dates = get_auditlog_list(start_date, src_hdfs_dir)
    for day in dates:
        if not day.endswith("2020-08-10"):
            logger.info(f"Processing {day} from {src_hdfs_dir}")
            copy_files_from_hdfs(f"{os.path.join(src_hdfs_dir, day)}", tmp_dir)
            logger.info(f"Uploading files in parallel from {tmp_dir}")
            succeeded = encrypt_and_upload_files_parallel(
                tmp_dir,
                s3_bucket,
                s3_prefix,
                hsm_key_id,
                aws_default_region,
                hsm_key_param_name,
                processes
            )
            clean_dir(tmp_dir)
            if succeeded:
                update_progress_file(progress_file, day.split("/")[-1])
            else:
                raise RuntimeError(f"Failed to process {day}")


def update_progress_file(progress_file, completed_date):
    with open(progress_file, "w") as out_file:
        out_file.write(completed_date)


def encrypt_and_upload_files_parallel(tmp_dir, s3_bucket, s3_prefix, hsm_key_id, aws_default_region,
                                      hsm_key_param_name, processes):
    hsm_key_file = b64decode(get_hsm_key(hsm_key_param_name, aws_default_region))
    futures = []
    names = []
    logger.info(f"Number of parallel processes: {processes}.")
    with ThreadPoolExecutor(max_workers=processes) as executor:
        for root, _, files in os.walk(tmp_dir):
            for name in files:
                logger.info(f"Submitting {name} to the executor")
                future = executor.submit(encrypt_and_upload_file, hsm_key_file, s3_bucket, s3_prefix,
                                         aws_default_region,
                                         root, name, hsm_key_id)
                futures.append(future)
                names.append(name)

        logger.info(f"Waiting for futures.")
        wait(futures)
        logger.info("Futures completed")
        executor.shutdown()
        succeeded = True
        for file, future in zip(names, futures):
            try:
                result = future.result()
                logger.info(f"{file} succeeded: {result}")
            except:
                logger.info(f"{file} failed with exception: '{future.exception()}'")
                succeeded = False
        return succeeded


def encrypt_and_upload_file(hsm_key_file, s3_bucket, s3_prefix, aws_default_region, root, name, hsm_key_id):
    hsm_key = RSA.import_key(hsm_key_file)
    session_key = get_random_bytes(16)
    # Session key gets encrypted with RSA HSM public key
    # This encryption cipher makes us compatible with DKS
    cipher_rsa = PKCS1_OAEP.new(key=hsm_key, hashAlgo=SHA256)
    enc_session_key = cipher_rsa.encrypt(session_key)
    # Data gets encrypted with AES session key (session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    in_file = os.path.join(root, name)
    out_file = in_file + ".gz.enc"
    with open(in_file, "rb") as fin, open(out_file, "wb") as fout:
        compressed_data = zlib.compress(fin.read())
        fout.write(cipher_aes.encrypt(compressed_data))
    s3_object_metadata = {
        "iv": b64encode(cipher_aes.nonce).decode(),
        "ciphertext": b64encode(enc_session_key).decode(),
        "datakeyencryptionkeyid": hsm_key_id,
    }
    upload_to_s3(out_file, s3_object_metadata, s3_bucket, s3_prefix, aws_default_region)


def get_auditlog_list(start_date, src_hdfs_dir):
    logger.info(f"Finding all files to process, start_date: {start_date}")
    if start_date is not None:
        logger.info("Excluding entries older than %s", start_date)
    try:
        process = subprocess.run(
            ["hdfs", "dfs", "-ls", "-C", src_hdfs_dir],
            check=True,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("Couldn't list auditlog entries in HDFS: %s", exc)
        raise exc
    # skip the last line of output as it's always blank
    alldates = process.stdout.split("\n")[0:-1]
    if start_date is None:
        dates = alldates
    else:
        dates = filter(lambda hdfsdir: filter_date(hdfsdir, start_date), alldates)

    return dates


def copy_files_from_hdfs(hdfs_dir, tmp_dir):
    logger.info("Retrieving %s from HDFS", hdfs_dir)
    os.makedirs(tmp_dir, exist_ok=True)
    try:
        subprocess.run(
            ["hdfs", "dfs", "-copyToLocal", hdfs_dir, tmp_dir],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("Couldn't copy files from HDFS: %s", exc)
        raise exc


def upload_to_s3(
        enc_file, s3_object_metadata, s3_bucket, s3_prefix, aws_default_region
):
    day = os.path.dirname(enc_file).split("/")[-1]
    destination_file_name = f"{s3_prefix}{day}/{os.path.basename(enc_file)}"
    logger.info("Uploading %s to s3://%s/%s", enc_file, s3_bucket, destination_file_name)
    s3_client = get_client("s3", aws_default_region)
    try:
        with open(enc_file, "rb") as data:
            s3_client.upload_fileobj(
                data,
                s3_bucket,
                destination_file_name,
                ExtraArgs={"Metadata": s3_object_metadata},
            )
            logger.info("Uploaded %s to s3://%s/%s", enc_file, s3_bucket, destination_file_name)
    except Exception as exc:
        logger.error("Error uploading %s to S3: %s", enc_file, exc)
        raise exc


def get_client(service_name, aws_default_region):
    return boto3.client(service_name, region_name=aws_default_region)


def get_hsm_key(hsm_key_param_name, aws_default_region):
    ssm_client = get_client("ssm", aws_default_region)
    return ssm_client.get_parameter(Name=hsm_key_param_name, WithDecryption=True)[
        "Parameter"
    ]["Value"]


def clean_dir(tmp_dir):
    if os.path.exists(tmp_dir):
        logger.info("Cleaning temp_dir")
        shutil.rmtree(tmp_dir)


def find_start_date(progress_file):
    start_date = None

    try:
        with open(progress_file, "r") as in_file:
            start_datestr = in_file.read().strip("\n")
            start_date = datetime.datetime.strptime(start_datestr, "%Y-%m-%d")
    except ValueError as exc:
        logger.error(
            "Couldn't parse date in %s, it should be in YYYY-MM-DD format",
            progress_file,
        )

        raise exc
    except IOError:
        logger.warning(
            "No progress file found at %s; processing all dates", progress_file
        )

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
        "--processes", type=int,
        required=False,
        help="How many processes to run in parallel",
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
    parser.add_argument(
        "--progress-file", required=True, help="A progress file location"
    )

    args = parser.parse_args()

    try:
        clean_dir(args.tmp)
        s_date = find_start_date(args.progress_file)
        main(
            s_date,
            args.src_hdfs_dir,
            args.tmp,
            args.s3_publish_bucket,
            args.s3_prefix,
            args.hsm_key_id,
            args.aws_default_region,
            args.hsm_key_param_name,
            args.progress_file,
            args.processes
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ExpiredTokenException":
            logger.warning("AWS credentials expired. Exiting")
        else:
            logger.error("Error calling AWS service: %s", exc)
            raise exc
    except Exception as exc:
        logger.error("Error processing files: %s", exc)
        raise exc
    finally:
        clean_dir(args.tmp)
