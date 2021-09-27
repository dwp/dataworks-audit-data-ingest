# dataworks-audit-data-ingest

## Ingest encrypted UC Kafka audit data into S3

After cloning this repo, please run:  
`make bootstrap`

This repository contains a script that was used within DataWorks to transfer data from the Crown platform to AWS so that it can be made available to the users via the Analytical environment.

## Usage

This process was performed for the historic audit and equalities data.

The script is not suitable for local running and is made to be run on the Crown platform itself. It will then look in the given `hdfs` location, encrypt the files with DKS, zip them and put them on S3.

As the Crown platform is being retired and the data has all been transferred now the script will likely not be needed again.
