//
//  OpenWatchEngine.swift
//  OpenWatch
//
//  Created by Confirmed, Inc. on 11/9/18.
//  Copyright © 2018 Confirmed, Inc. All rights reserved.
//

import Cocoa
import AWSS3
import AWSCore

class OpenWatchEngine: NSObject {

    private override init() {
        super.init()
    }
    
    /*
     * Requires AWS keys to validate signature of digest files
     * Setup AWS SDK for when we use them
     */
    init(awsAccessKey : String, awsSecretKey : String, awsRegion : String) {
        super.init()
        accessKey = awsAccessKey
        accessSecret = awsSecretKey
        credentialsProvider = AWSStaticCredentialsProvider.init(accessKey: accessKey, secretKey: accessSecret)
        //credentialsProvider?.refresh()
        let region = CloudTrailService.getTypeFromRegion(region: awsRegion.lowercased())
        
        let defaultServiceConfiguration = AWSServiceConfiguration(region: region, credentialsProvider: credentialsProvider)
        
        AWSS3TransferUtility.remove(forKey: "\(OpenWatchEngine.sessionKey)")
        AWSS3.remove(forKey: "\(OpenWatchEngine.sessionKey)")
        
        OpenWatchEngine.sessionKey = OpenWatchEngine.sessionKey + 1
        
        AWSS3TransferUtility.register(with: defaultServiceConfiguration!, forKey: "\(OpenWatchEngine.sessionKey)")
        AWSS3.register(with: defaultServiceConfiguration!, forKey: "\(OpenWatchEngine.sessionKey)")
        
        calculateDownloadTask.estimatedUnitsOfWork = 200
        calculateDownloadTask.taskName = "Calculating download size"
        downloadTask.estimatedUnitsOfWork = 1500
        downloadTask.taskName = "Downloading all CloudTrail files"
        processDigestsTask.estimatedUnitsOfWork = 200
        processDigestsTask.taskName = "Processing digest files"
        processLogsTask.estimatedUnitsOfWork = 100
        processLogsTask.taskName = "Processing log files"
    }
    
    /*
     * Parent method to begin processing
     * Download files to /tmp/ if no local folder required
     */
    func beginAudit(from : Date, until : Date, sourceFolderPath : String?, progressUpdateCallback: @escaping () -> Void, auditFinished: @escaping () -> Void) {
        violations.removeAll()
        sourceRepos.removeAll()
        startDate = from
        endDate = until
        auditFinishedBlock = auditFinished
        progressUpdate = progressUpdateCallback
        failureToAuditReason = nil
        if let localSource = sourceFolderPath {
            rootFolderPath = localSource.hasSuffix("/") ? localSource : localSource.appendingFormat("/")
            shouldDownload = false
        }
        else {
            shouldDownload = true
            rootFolderPath = downloadDirectory
        }
        
        var didCompleteBucketCall = false
        CloudTrailService.getCloudTrailBucket(credentialsProvider: credentialsProvider!, completion: { bucketName in
            if bucketName == nil {
                self.failAbilityToAudit(reason:"Could not get bucket name. Please check AWS Credentials.")
            } else {
                self.cloudTrailBucket = bucketName
            }
            didCompleteBucketCall = true
        })
        
        while !didCompleteBucketCall { //catch bad AWS key early
            sleep(1)
        }
        if self.didFailAbilityToAudit() {return}
        
        
        auditTask.tasks?.removeAll()
        processLogsTask.resetTaskProgress()
        processDigestsTask.resetTaskProgress()
        calculateDownloadTask.resetTaskProgress()
        downloadTask.resetTaskProgress()
        self.auditTask.tasks = [processDigestsTask, processLogsTask]
        
        DispatchQueue.global().async {
            var didGetAccountID = false
            CloudTrailService.getAccountID(credentialsProvider: self.credentialsProvider!, region: "us-east-1", completion: { accountID in
                self.accountID = accountID
                didGetAccountID = true
            })
            
            while !didGetAccountID {
                sleep(1)
            }
            
            if self.accountID == nil {
                self.failAbilityToAudit(reason: "Could not retrieve Account ID")
                return
            }
            
            if self.shouldDownload {
                self.auditTask.tasks = [self.calculateDownloadTask, self.downloadTask, self.processDigestsTask, self.processLogsTask]
                self.findAndDownloadAllFiles()
                
                if self.didFailAbilityToAudit() { return }
            }
            
            self.processDigests()
            auditFinished()
        }
    }
    
    func didFailAbilityToAudit() -> Bool {
        return failureToAuditReason != nil
    }
    
    func failAbilityToAudit(reason: String) {
        failureToAuditReason = reason
        
        //clear out all operations
        digestQueue.cancelAllOperations()
        logQueue.cancelAllOperations()
        setupDigestProcessingQueue.cancelAllOperations()
        
        //force finish every task
        if auditTask.tasks != nil {
            for task in auditTask.tasks! {
                task.markAsFinished()
            }
        }

        auditFinishedBlock?()
        
    }
    
    //MARK: - CloudTrail Digest
    /*
        * Requires a rigid directory structure
        * Cycle through each region we support
        * Find latest digest file for each region
        * Pass to chaining method explained below
     */
    private func processDigests() {
        let regions = OpenWatchEngine.supportedRegions
        let fileManager = FileManager.default
        setupDigestProcessingQueue.maxConcurrentOperationCount = OpenWatchEngine.supportedRegions.count
        
        digestQueue.maxConcurrentOperationCount = 0 //pause processing until public keys and signatures are retrieved and total number of digest files are calculated
        logQueue.maxConcurrentOperationCount = 0
        
        publicKeys.removeAll()
        rootSignatures.removeAll()
        
        //determine Account ID
        let accountPath = "\(self.rootFolderPath)AWSLogs/"
        guard let accountIDs = try? FileManager.default.contentsOfDirectory(atPath: accountPath) else {
            self.failAbilityToAudit(reason: "Could not find Account ID in directory structure.")
            return
        }
        let sortedIDs = accountIDs.sorted { $0 > $1 }
        accountID = sortedIDs.first
        
        if accountID == nil {
            self.failAbilityToAudit(reason: "Could not find Account ID in directory structure.")
            return
        }
        
        for region in regions {
            self.setupDigestProcessingQueue.addOperation {
                if self.didFailAbilityToAudit() {return}
                let regionPath = "\(self.rootFolderPath)AWSLogs/\(self.accountID!)/CloudTrail-Digest/\(region)/"
                
                guard let enumerator:FileManager.DirectoryEnumerator = fileManager.enumerator(atPath: regionPath) else {
                    self.failAbilityToAudit(reason: "Could not find region directory structure.")
                    return
                }
                
                var reversedFiles = enumerator.allObjects as! [String]
                reversedFiles = reversedFiles.sorted { $0 > $1 }

                self.processDigestsTask.numberOfSubtasks += reversedFiles.count
                
                var firstDigestInChain = reversedFiles.first
                firstDigestInChain = firstDigestInChain?.replacingOccurrences(of: self.rootFolderPath, with: "")
                firstDigestInChain = "AWSLogs/\(self.accountID!)/CloudTrail-Digest/\(region)/\(firstDigestInChain!)"
                
                var rootSignatureCompleted = false
                var regionRootSignature : RegionRootSignature? = nil
                self.getMetadataSignature(forKey: firstDigestInChain!, completion: { signature in
                    regionRootSignature = RegionRootSignature(region: region, signature: signature!)
                    self.rootSignatures.append(regionRootSignature!)
                    rootSignatureCompleted = true
                    print("returned here for region \(region)")
                })
                
                while !rootSignatureCompleted {
                    sleep(1)
                    if self.didFailAbilityToAudit() { return }
                }
                
                print("Finished here for region \(region), \(firstDigestInChain)")
                self.digestQueue.addOperation {
                    if self.didFailAbilityToAudit() {return}
                    self.processDigestChain(region: region, firstDigestInChain: firstDigestInChain!, rsaSignature: (regionRootSignature?.signature)!, isRoot: true)
                }
            }
        }
        setupDigestProcessingQueue.waitUntilAllOperationsAreFinished()
        self.updateEstimatedPercentComplete()
        
        for region in regions {
            setupDigestProcessingQueue.addOperation {
                var didCompleteCall = false
                CloudTrailService.getPublicKeys(credentialsProvider: self.credentialsProvider!, region: region, completion: { regionKeys in
                    print("Received keys \(region) : \(regionKeys.count)")
                    self.publicKeys.append(contentsOf: regionKeys)
                    didCompleteCall = true
                })
                
                while !didCompleteCall {
                    sleep(1)
                    if self.didFailAbilityToAudit() { return }
                }
            }
        }
        
        setupDigestProcessingQueue.waitUntilAllOperationsAreFinished()
        print("Received public keys: \(self.publicKeys.count)")
        self.digestQueue.maxConcurrentOperationCount = 2 //start processing digest chains
        self.digestQueue.waitUntilAllOperationsAreFinished()
        sleep(1)
        self.processDigestsTask.markAsFinished()
        self.logQueue.maxConcurrentOperationCount = 3 //digest chain is the bottle neck, begin only after that is finished digest
        self.logQueue.waitUntilAllOperationsAreFinished()
        self.processLogsTask.markAsFinished()
        
    }
    
    /*
     * This method checks that we are getting recent digests
     * If not, we need to error, as they may have been deleted
     * Because of chaining structure, this can catch edge case
     */
    private func calculateDigestStartTime(region : String, digest : Digest) {
        let digestEndTime = digest.digestEndTime
        let awsDateFormat = DateFormatter()
        awsDateFormat.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        let stringGivenDate = awsDateFormat.date(from: digestEndTime!)
        let timeSinceNow = Int((stringGivenDate?.timeIntervalSinceNow)!)
        
        //find the oldest set of logs for a region (worst case for how outdated the logs are)
        if abs(furthestStartLog) < abs(timeSinceNow) {
            furthestStartLog = abs(timeSinceNow)
        }

    }
    
    /*
     * Start at latest digest file
     * Validate signature of digest file
        * Get public key from AWS
     * Validate signature of each log file
     * Process each log file for violations
     * If date is within scope of audit ->
        * Continue chaining using previous digest field
     * Region is only used for logging
     */
    private func processDigestChain(region : String, firstDigestInChain : String, rsaSignature: String, isRoot : Bool) {
        let fullPath = rootFolderPath + firstDigestInChain
        let fileURL = URL.init(fileURLWithPath: fullPath)
        
        if let content = Data.uncompressedContents(fileURL: fileURL) {
            if let digest = try? JSONDecoder().decode(Digest.self, from: content) {
                if isRoot {calculateDigestStartTime(region: region, digest: digest)}
                validateIntegrityOfDigestFile(digest: digest, digestContents: content, signature: rsaSignature, fullPath: fullPath)
                for logFile in digest.logFiles! {
                    let logFilePath = "\(rootFolderPath)\(logFile.s3Object!)"
                    let logFileURL = URL.init(fileURLWithPath: logFilePath)
                    if let logContent = Data.uncompressedContents(fileURL: logFileURL), let digestString = String.init(bytes: logContent, encoding: .utf8)  {
                        if logFile.hashValue != digestString.sha256() {
                            print("Wrong SHA-256 for File \(logFilePath)")
                            violations.append(Violation(name: "Wrong SHA-256", eventTime: nil, eventName: nil, awsRegion: region, sourceIP: nil, filePath: logFilePath))
                        }
                        processLogsTask.numberOfSubtasks += 1
                        logQueue.addOperation {
                            if self.didFailAbilityToAudit() {return}
                            self.processLogFile(fullPath:logFilePath, digestFilePath: fullPath)
                        }
                    }
                    else {
                        print("Missing log: \(logFilePath) in digest: \(fullPath)")
                        violations.append(Violation(name: "Missing Log File", eventTime: nil, eventName: nil, awsRegion: region, sourceIP: nil, filePath: logFilePath))
                    }
                    
                }
                
                updateEstimatedPercentComplete()
                digestQueue.addOperation {
                    self.continueChainingIfNecessary(region: region, currentDigest: digest)
                }
            }
            else {
                //Incorrect format, mark as a violation for now
                violations.append(Violation(name: "Missing or malformed digest record", eventTime: nil, eventName: nil, awsRegion: region, sourceIP: nil, filePath: fullPath))
                
            }
        }
        else {
            violations.append(Violation(name: "Missing or malformed digest record", eventTime: nil, eventName: nil, awsRegion: region, sourceIP: nil, filePath: fullPath))
        }
        
    }
    
    func getMetadataSignature(forKey: String, completion: @escaping(_ signature: String?) -> Void) -> Void {
        let s3 = AWSS3.s3(forKey: "\(OpenWatchEngine.sessionKey)")
        let request = AWSS3HeadObjectRequest()
        request?.bucket = cloudTrailBucket
        request?.key = forKey

        s3?.headObject(request).continue({ (task) -> AnyObject? in
            if let error = task?.error {
                print("Error to find file: \(error)")
                completion(nil)
                
            } else {
                let output = task?.result as! AWSS3HeadObjectOutput
                let signature = output.metadata["signature"] as! String
                completion(signature)
            }
            return task
        })
    }
    
    /*
     
     */
    private func validateIntegrityOfDigestFile(digest: Digest, digestContents : Data, signature: String, fullPath: String) {
        
        if digest.previousDigestSignature == nil { //need to figure out what to do for end of chain
            return
        }
        var error: Unmanaged<CFError>?
        let dateString = digest.digestEndTime
        let s3Object = digest.digestS3Object!
        let s3Bucket = digest.digestS3Bucket!
        let sha256 = digestContents.sha256().hexadecimalString().lowercased()
        //for digest signature, should just get first one and then chain previous
        let digestSignature = signature
        let previousSignature = digest.previousDigestSignature!
        
        let dataSigningString = "\(dateString!)\n\(s3Bucket)/\(s3Object)\n\(sha256)\n\(previousSignature)"
        
        var fingerprint = digest.digestPublicKeyFingerprint
        var publicKey : String? = nil
        for key in publicKeys {
            if key.fingerprint == fingerprint {
                publicKey = key.key
            }
        }
        
        if publicKey == nil {
            violations.append(Violation(name: "Couldn't find public key with fingerprint", eventTime: nil, eventName: nil, awsRegion: nil, sourceIP: nil, filePath:fullPath))
            return
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048
        ]
        
        let publicKeyData = Data(base64Encoded: publicKey!)
        let seckey = SecKeyCreateWithData(publicKeyData! as CFData, attributes as CFDictionary, &error)
        
        let result = Utils.verifyBytesSHA256withRSA(inputData: dataSigningString.data(using: .utf8)!, signature: digestSignature.dataFromHexString()!, publicKey: seckey!)
        
        if !result {
            print("Failed RSA signature verification")
            violations.append(Violation(name: "Corrupted Trail File", eventTime: nil, eventName: nil, awsRegion: nil, sourceIP: nil, filePath:fullPath))
        }
        
    }
    
    /*
        * Check if there is a previous digest field
        * If so, check it is within audit date range
        * If not both, stop chaining
     */
    private func continueChainingIfNecessary(region: String, currentDigest : Digest) {
        let digestEndTime = currentDigest.digestEndTime
        let awsDateFormat = DateFormatter()
        awsDateFormat.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        let stringGivenDate = awsDateFormat.date(from: digestEndTime!)
        
        if stringGivenDate! >= startDate && currentDigest.previousDigestS3Object != nil {
            self.processDigestChain(region: region, firstDigestInChain: currentDigest.previousDigestS3Object!, rsaSignature: currentDigest.previousDigestSignature!, isRoot: false)
            self.processDigestsTask.completedSubtasks += 1
            
        }
    }
    
    //MARK: - Process Log Files
    /*
        * Processes log files for record violations
        * Digest file path is only for debugging purposes
     */
    func processLogFile(fullPath : String, digestFilePath : String) {
        
        let gzipURL = URL.init(fileURLWithPath: fullPath)
        if let content = try? Data(contentsOf: gzipURL), let gzipContent = content.isGzipped ? try? content.gunzipped() : content {
            if let zipCall = try? JSONDecoder().decode(Records.self, from: gzipContent) {
                for (index, awsCall) in zipCall.records.enumerated() {
                    processAWSCall(logFilePath:fullPath, awsCall: awsCall)
                }
            }
            else {
                print("Couldn't process log file: \(fullPath)\nDigest file: \(digestFilePath)\n\n")
                violations.append(Violation(name: "Couldn't load record", eventTime: nil, eventName: nil, awsRegion: nil, sourceIP: nil, filePath:fullPath))
            }
        }
        else {
            //failed to process log
            violations.append(Violation(name: "Missing Log Records", eventTime: nil, eventName: nil, awsRegion: nil, sourceIP: nil, filePath:fullPath))
        }
        
        self.processLogsTask.completedSubtasks += 1
        updateEstimatedPercentComplete()
    }
    
    //MARK: - CloudTrail Rules
    
    func processAWSCall(logFilePath: String, awsCall : APICall) {
        if sshState == .on {
            checkForStartingRemoteSession(logFilePath: logFilePath, awsCall: awsCall)
        }
        if safeBringupState == .on {
            checkForSafeBringup(logFilePath: logFilePath, awsCall: awsCall)
        }
        if roleState == .on {
            checkForRolePolicy(logFilePath: logFilePath, awsCall: awsCall)
        }
        if getParametersState == .on {
            checkForSecretLookup(logFilePath: logFilePath, awsCall: awsCall)
        }
        if flowLogState == .on {
            checkForFlowLogs(logFilePath: logFilePath, awsCall: awsCall)
        }
        if runCommandState == .on {
            checkForRunCommand(logFilePath: logFilePath, awsCall: awsCall)
        }
        if deleteLogsState == .on {
            checkForDeleteLogs(logFilePath: logFilePath, awsCall: awsCall)
        }
        
        showDeployedCodeIfLatest(logFilePath: logFilePath, awsCall: awsCall)
    }
    
    /*
        * Update list of latest deployed code
        * Only set if not existent (to show the latest URL since we chain backwards)
     */
    func showDeployedCodeIfLatest(logFilePath: String, awsCall : APICall) {
        if awsCall.eventName == "CreateDeployment" {
            if let appName = awsCall.requestParameters?.applicationName, let key = awsCall.requestParameters?.revision?.s3Location?.key, let bucket = awsCall.requestParameters?.revision?.s3Location?.bucket {
                if sourceRepos[appName] == nil {
                    sourceRepos[appName] = "https://s3.amazonaws.com/\(bucket)/\(key)"
                }
            }
        }
    }
    
    func checkForSecretLookup(logFilePath: String, awsCall : APICall) {
        if (awsCall.userIdentity?.type == "Root" || awsCall.userIdentity?.type == "IAMUser") && awsCall.eventSource == "ssm.amazonaws.com" && (awsCall.eventName == "GetParameters" || awsCall.eventName == "GetParameter" || awsCall.eventName == "GetParametersByPath") {
            
            let vio = Violation.init(name: "Secret looked up",
                                     eventTime: awsCall.eventTime,
                                     eventName: awsCall.eventName,
                                     awsRegion: awsCall.awsRegion,
                                     sourceIP: awsCall.sourceIPAddress,
                                     filePath:logFilePath)
            
            violations.append(vio)
        }
    }
    
    func checkForRolePolicy(logFilePath: String, awsCall : APICall) {
        if let pd = awsCall.requestParameters?.policyDocument, let pdStatement = pd.statement {
            for statement in pdStatement {
                if statement.principal?.aws != nil {
                    let vio = Violation.init(name: "Role policy change",
                                             eventTime: awsCall.eventTime,
                                             eventName: awsCall.eventName,
                                             awsRegion: awsCall.awsRegion,
                                             sourceIP: awsCall.sourceIPAddress,
                                             filePath:logFilePath)
                    
                    violations.append(vio)
                }
            }
        }
        
        if let pd = awsCall.requestParameters?.assumeRolePolicyDocument, let pdStatement = pd.statement {
            for statement in pdStatement {
                if statement.principal?.aws != nil {
                    let vio = Violation.init(name: "Assume role policy change",
                                             eventTime: awsCall.eventTime,
                                             eventName: awsCall.eventName,
                                             awsRegion: awsCall.awsRegion,
                                             sourceIP: awsCall.sourceIPAddress,
                                             filePath:logFilePath)
                    violations.append(vio)
                }
            }
        }
    }
    
    func checkForSafeBringup(logFilePath: String, awsCall : APICall) {
        if awsCall.eventSource == "ec2.amazonaws.com" && awsCall.eventName == "RunInstances" {
            if let items = awsCall.requestParameters?.instancesSet?.items {
                for (index, item) in items.enumerated() {
                    if item.keyName != nil {
                        let vio = Violation.init(name: "SSH enabled on bringup",
                                                 eventTime: awsCall.eventTime,
                                                 eventName: awsCall.eventName,
                                                 awsRegion: awsCall.awsRegion,
                                                 sourceIP: awsCall.sourceIPAddress,
                                                 filePath:logFilePath)
                        violations.append(vio)
                    }
                }
            }
        }
    }
    
    func checkForStartingRemoteSession(logFilePath: String, awsCall : APICall) -> Void {
        if awsCall.eventSource == "ssm.amazonaws.com" && awsCall.eventName == "StartSession" {
            let vio = Violation.init(name: "SSH session initiated",
                                     eventTime: awsCall.eventTime,
                                     eventName: awsCall.eventName,
                                     awsRegion: awsCall.awsRegion,
                                     sourceIP: awsCall.sourceIPAddress,
                                     filePath:logFilePath)
            violations.append(vio)
        }
    }
    
    func checkForFlowLogs(logFilePath: String, awsCall : APICall) -> Void {
        if awsCall.eventSource == "ec2.amazonaws.com" && awsCall.eventName == "CreateFlowLogs" {
            let vio = Violation.init(name: "Created flow logs",
                                     eventTime: awsCall.eventTime,
                                     eventName: awsCall.eventName,
                                     awsRegion: awsCall.awsRegion,
                                     sourceIP: awsCall.sourceIPAddress,
                                     filePath:logFilePath)
            violations.append(vio)
        }
    }
    
    func checkForRunCommand(logFilePath: String, awsCall : APICall) -> Void {
        if awsCall.eventName == "SendCommand" {
            let vio = Violation.init(name: "Run command executed",
                                     eventTime: awsCall.eventTime,
                                     eventName: awsCall.eventName,
                                     awsRegion: awsCall.awsRegion,
                                     sourceIP: awsCall.sourceIPAddress,
                                     filePath:logFilePath)
            violations.append(vio)
        }
    }
    
    func checkForDeleteLogs(logFilePath: String, awsCall : APICall) -> Void {
        if (awsCall.eventName == "DeleteLogGroup" || awsCall.eventName == "DeleteLogStream") {
            let vio = Violation.init(name: "LogGroup/LogStream Deleted",
                                     eventTime: awsCall.eventTime,
                                     eventName: awsCall.eventName,
                                     awsRegion: awsCall.awsRegion,
                                     sourceIP: awsCall.sourceIPAddress,
                                     filePath:logFilePath)
            violations.append(vio)
        }
    }
    
    /*
     * Audit can take quite a bit of time
     * Update caller appropriately so they know it is working
     * Download is the majority of time
     * Reweight if we are using S3 to download files
     * Call this method instead of progress update
        * Will call progress update after variables updated
     */
    func updateEstimatedPercentComplete() {
        progressUpdate?()
    }
 
    
    //MARK: - S3 Sync
    /*
     * Recursive method to get all files from a bucket
     */
    func getAllFilesFromS3(prefix : String?, marker: String?, result: @escaping (_ keys: [AWSS3Object]) -> Void) {
        let s3 = AWSS3.s3(forKey: "\(OpenWatchEngine.sessionKey)")
        
        
        let objReq = AWSS3ListObjectsRequest.init()
        objReq?.bucket = self.cloudTrailBucket
        objReq?.delimiter = "\\"
        objReq?.prefix = prefix
        objReq?.marker = marker
        
        
        s3?.listObjects(objReq).continue({ task in
            if let listObjectsOutput = task?.result as? AWSS3ListObjectsOutput {
                if listObjectsOutput.isTruncated.boolValue {
                    usleep(250000) //delay for rate limiting
                    self.getAllFilesFromS3(prefix: prefix, marker: listObjectsOutput.nextMarker, result: { keys in
                        var obj = listObjectsOutput.contents as! [AWSS3Object]
                        obj.append(contentsOf: keys)
                        result(obj)
                    })
                }
                else {
                    if listObjectsOutput.contents != nil {
                        let obj = listObjectsOutput.contents as! [AWSS3Object]
                        result(obj)
                    }
                    else {
                        result([])
                    }
                }
            }
            else {
                result([]) //zero
            }
            if let e = task?.error {
                print("Error listing objects \(e)")
            }
            
            return nil
        })
    }
    
    func findAndDownloadAllFiles() -> Void {
        let transferUtility = AWSS3TransferUtility.s3TransferUtility(forKey: "\(OpenWatchEngine.sessionKey)")
        
        transferUtility?.getAllTasks().continue({ task in
            var res = task?.result as! Array<AWSS3TransferUtilityDownloadTask>
            for t in res {
                t.cancel() //clear all old tasks that can slow down process
            }
            print("Got all tasks with error \(task?.error)")
            
            return nil
        })
        
        
        var currentProcessedDate = startDate
        var logFiles = [AWSS3Object]()
        var digestFiles = [AWSS3Object]()
        
        let fileManager = FileManager.default
        do {
            try fileManager.removeItem(atPath: downloadDirectory)
        }
        catch let error as NSError {
            print("Could not delete folder: \(error)")
        }
        calculateDownloadTask.numberOfSubtasks = 1 //start at 1, the parent task to set up async calls
        downloadTask.numberOfSubtasks = 1
        calculateDownloadTask.completedSubtasks = 0
        downloadQueueProcessingQueue.maxConcurrentOperationCount = 2 //limit to 2 because of AWS API limits
        
        while currentProcessedDate.timeIntervalSince(self.endDate) < 86399.999999 { //get up to 1 day ahead for time zones
            let calendar = Calendar.current
            
            let year = calendar.component(.year, from: currentProcessedDate)
            let month = calendar.component(.month, from: currentProcessedDate)
            let day = calendar.component(.day, from: currentProcessedDate)
            
            for region in OpenWatchEngine.supportedRegions {
                self.calculateDownloadTask.numberOfSubtasks += 2 //one for logs, one for digest
                let prefixLogs = "AWSLogs/\(self.accountID!)/CloudTrail/\(region)/\(year)/\(String(format: "%02d", month))/\(String(format: "%02d", day))"
                let prefixDigest = "AWSLogs/\(self.accountID!)/CloudTrail-Digest/\(region)/\(year)/\(String(format: "%02d", month))/\(String(format: "%02d", day))"
                
                downloadQueueProcessingQueue.addOperation {
                    var completedTask = false
                    self.getAllFilesFromS3(prefix: prefixLogs, marker: nil, result: { keys in
                        //print("Log Prefix: \(prefixLogs) Log Keys: \(keys.count)")
                        Utils.synced(self, closure: {
                            logFiles.append(contentsOf: keys)
                        })
                        self.calculateDownloadTask.completedSubtasks += 1
                        self.updateEstimatedPercentComplete()
                        completedTask = true
                    })
                    
                    while(!completedTask) {
                        usleep(250000)
                    }
                }
                
                downloadQueueProcessingQueue.addOperation {
                    var completedTask = false
                    self.getAllFilesFromS3(prefix: prefixDigest, marker: nil, result: { keys in
                        //print("Prefix: \(prefixLogs) Digest Keys: \(keys.count)")
                        Utils.synced(self, closure: {
                            digestFiles.append(contentsOf: keys)
                        })
                        self.calculateDownloadTask.completedSubtasks += 1
                        self.updateEstimatedPercentComplete()
                        completedTask = true
                    })
                    while(!completedTask) {
                        usleep(250000)
                    }
                }
                
            }
            
            currentProcessedDate = Calendar.current.date(byAdding: .day, value: 1, to: currentProcessedDate)!
            //print("Time interval here \(currentProcessedDate.timeIntervalSince(self.endDate))")
        }
        

        sleep(5)
        downloadQueueProcessingQueue.waitUntilAllOperationsAreFinished()
        calculateDownloadTask.completedSubtasks += 1 //finished parent async queue setup task
        while(!calculateDownloadTask.isFinished()) {
            sleep(1)
            if self.didFailAbilityToAudit() { return }
        }
        
        
        print("Got all files - \(logFiles.count)")
        print("Got all digests - \(digestFiles.count)")
        
        logFiles.append(contentsOf: digestFiles)
        
        downloadTask.numberOfSubtasks = logFiles.count
        calculateDownloadTask.markAsFinished()
        self.updateEstimatedPercentComplete()
        
        //now download the files into a folder
        //should try transfer utility??
        
        downloadQueueProcessingQueue.maxConcurrentOperationCount = 10 //limit to 2 because of AWS API limits
        
        let logFileChunks = logFiles.chunk(500)
        for chunk in logFileChunks {
            downloadQueueProcessingQueue.addOperation {
                autoreleasepool {
                    for obj in chunk {
                        
                        let outputDirectory = "\(self.downloadDirectory)/\(Utils.stripFileComponent(obj.key!))"
                        let outputPath = "\(self.downloadDirectory)/\(obj.key!)"
                        let outputURL = URL.init(fileURLWithPath: outputPath)
                        let dReq = AWSS3TransferManagerDownloadRequest.init()
                        dReq?.bucket = self.cloudTrailBucket
                        dReq?.key =  obj.key
                        dReq?.downloadingFileURL = outputURL
                        
                        do {
                            try FileManager.default.createDirectory(atPath: outputDirectory, withIntermediateDirectories: true, attributes: nil)
                        }
                        catch let error as NSError {
                            NSLog("Unable to create directory \(error.debugDescription)")
                        }
                        
                        transferUtility?.download(to: outputURL, bucket: self.cloudTrailBucket!, key: obj.key, expression: nil, completionHander: { task, location, data, error in
                            
                            if error != nil {
                                print("Download error \(String(describing: error))")
                            }
                            Utils.synced(self, closure: {
                                self.downloadTask.completedSubtasks += 1
                            })
                            self.updateEstimatedPercentComplete()
                        })
                    }
                }
            }
        }
        
        sleep(5)
        if logFiles.count == 0 || digestFiles.count == 0 {
            self.failAbilityToAudit(reason: "No logs or digests (Is CloudTrail Region correct?)")
            return
        }
        while(!downloadTask.isFinished()) {
            sleep(1)
            if self.didFailAbilityToAudit() { return }
        }
        
        print("Downloaded everything")
    }
    
    //MARK: - MISC
    func estimatedPercentageComplete() -> Double {
        return auditTask.estimatePercentageComplete()
    }
    
    //MARK: - VARIABLES
    private(set) var accessKey = ""
    private(set) var accessSecret = ""
    
    
    private(set) var auditTask = AuditTask()
    private(set) var calculateDownloadTask = Task()
    private(set) var downloadTask = Task()
    private(set) var processDigestsTask = Task()
    private(set) var processLogsTask = Task()
    
    var failureToAuditReason : String? = nil
    var shouldDownload = false
    let downloadDirectory = "/tmp/OpenWatchAudit/"
    var rootFolderPath : String = "/"
    var startDate : Date = Date.init()
    var endDate : Date = Date.init()
    var progressUpdate : (() -> Void)? = nil
    var auditFinishedBlock : (() -> Void)? = nil
    var cloudTrailBucket : String? = nil
    
    
    var sourceRepos = [String:String]()
    var violations = [Violation]()
    var publicKeys = [PublicKey]()
    var rootSignatures = [RegionRootSignature]()
    var digestQueue = OperationQueue.init()
    var logQueue = OperationQueue.init()
    var setupDigestProcessingQueue = OperationQueue.init()
    var downloadQueueProcessingQueue = OperationQueue.init()
    
    var getParametersState = NSButton.StateValue.on
    var safeBringupState = NSButton.StateValue.on
    var roleState = NSButton.StateValue.on
    var sshState = NSButton.StateValue.on
    var flowLogState = NSButton.StateValue.on
    var runCommandState = NSButton.StateValue.on
    var deleteLogsState = NSButton.StateValue.on
    var credentialsProvider : AWSStaticCredentialsProvider? = nil
    
    var furthestStartLog : Int = 0
    
    var accountID : String? = nil //need to fetch this from AWS in the future
    //if changing account ID, also have to change endpoint AWSRegionType in init of engine
    
    static var sessionKey : Int = 0
    
    static let supportedRegions = ["ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", /*"eu-west-3",*/ "sa-east-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2"]
    
}

