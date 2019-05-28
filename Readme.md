# Open Watch

Open Watch is an open source library to determine whether a server's configuration follows the latest Openly Operated principles. These include:

* **Disabling SSH or direct machine access
* **No database password or other secrets access
* **Not allowing users to assume roles intended for machines
* **Not allowing any remote sessions
* **Disabling flow logs
* **Not allowing any custom commands on machines


## How To Run

To get started, download the source code (or binary). Once open, select the start date (the end date is fixed to today) and either choose a local folder or fetch the cloud trail logs from the AWS account preloaded. If you want to choose a different AWS account, please build from source and make the following three changes:

1) Enter the AWS Keys in Storybard (For credentials for Confirmed VPN, please e-mail the team)
2) Change the hardcoded Account ID
3) Change the AWS Endpoint Region to that of the AWS account

Please keep in mind this involves parsing through gigabytes of log data and can take over an hour to run, depending on your Internet connection. Please make sure you have the latest logs to ensure the most accurate and up-to-date audit.

We recommend downloading the log files as one compressed file from the audited website. Once uncompressed on your machine, you can select the logs folder in OpenWatch. Though Open Watch can download logs from S3 directly, it will take much longer to traverse the CloudTrail bucket and download each file.


## How To Build

1) Run pod install
2) Open OpenWatch.xcworkspace
3) Compile and run

## Results

Ideally, the results look like this:

![Successful Audit](https://github.com/OpenlyOperated/Open-Watch/raw/master/OpenWatchUI.png)

If you had any issues, they will be listed out at the end of the audit (it may not complete the audit if the logs are corrupted or not present, so if you encounter an error please ensure that you have all the appropriate logs).

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details



