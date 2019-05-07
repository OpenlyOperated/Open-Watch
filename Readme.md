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

Please keep in mind this involves parsing through over 5 gigabytes of log data and can take 30-60 minutes to run, depending on your Internet connection. Please make sure you have the latest logs to ensure the most accurate and up-to-date audit.


## Results
Ideally, the results look like this:

![Successful Audit](https://s3.us-east-2.amazonaws.com/confirmedclients/OpenWatchOutput.png)

If you had any issues, they will be listed out at the end of the audit (it may not complete the audit if the logs are corrupted or not present, so if you encounter an error please ensure that you have all the appropriate logs).

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details



