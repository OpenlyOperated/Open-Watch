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
        
        defaultServiceConfiguration = AWSServiceConfiguration(region: region, credentialsProvider: credentialsProvider)
        
        endpoint = AWSEndpoint.init(region: defaultServiceConfiguration!.regionType, service: .S3, useUnsafeURL: false)
        
        AWSS3.remove(forKey: "\(OpenWatchEngine.sessionKey)")
        
        OpenWatchEngine.sessionKey = OpenWatchEngine.sessionKey + 1
        AWSS3.register(with: defaultServiceConfiguration, forKey: "\(OpenWatchEngine.sessionKey)")

        
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
            
            self.s3Sync = S3Sync.init(
                credentialsProvider: (self.defaultServiceConfiguration?.credentialsProvider)!,
                accountID: self.accountID!,
                bucket: self.cloudTrailBucket!,
                endpoint: self.endpoint!,
                downloadDirectory: self.downloadDirectory,
                startDate: self.startDate,
                endDate: self.endDate
            )
            
            if self.shouldDownload {
                self.auditTask.tasks = [self.calculateDownloadTask, self.downloadTask, self.processDigestsTask, self.processLogsTask]
                
                self.s3Sync?.findAndDownloadAllFiles(
                    progressUpdateCallback: { calculateTotalDownloadTasks, completedCalculateTotalDownloadTasks, totalDownloadTasks, completedDownloadTasks, errorMessage in
                        
                        self.calculateDownloadTask.numberOfSubtasks = calculateTotalDownloadTasks
                        self.calculateDownloadTask.completedSubtasks = completedCalculateTotalDownloadTasks
                        
                        
                        self.downloadTask.numberOfSubtasks = totalDownloadTasks
                        self.downloadTask.completedSubtasks = completedDownloadTasks
                        
                        self.updateEstimatedPercentComplete()
                        if let err = errorMessage {
                            self.failAbilityToAudit(reason: err)
                        }
                })
                
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
        s3Sync?.shouldEndS3Sync = true
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
    
    private func allFilesInDirectory(path : String) -> [String]? {
        let fileManager = FileManager.default
        guard let regionEnumerator:FileManager.DirectoryEnumerator = fileManager.enumerator(atPath: path) else {
            self.failAbilityToAudit(reason: "Could not find region directory structure.")
            return nil
        }
        
        var allReversedFiles = regionEnumerator.allObjects as! [String]
        allReversedFiles = allReversedFiles.sorted { $0 > $1 }
        
        for index in stride(from: allReversedFiles.count - 1, through: 0, by: -1) {
            let fileManager = FileManager.default
            var isDir : ObjCBool = false
            let file = allReversedFiles[index]
            if fileManager.fileExists(atPath: "\(path)\(file)", isDirectory:&isDir) {
                if isDir.boolValue {
                    allReversedFiles.remove(at: index)
                }
            }
        }
        
        return allReversedFiles
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
                
                let calendar = Calendar.current
                
                let year = calendar.component(.year, from: self.endDate)
                let month = calendar.component(.month, from: self.endDate)
                let day = calendar.component(.day, from: self.endDate)
                
                let endDatePath = "\(self.rootFolderPath)AWSLogs/\(self.accountID!)/CloudTrail-Digest/\(region)/\(year)/\(String(format: "%02d", month))/\(String(format: "%02d", day))"
                let regionPath = "\(self.rootFolderPath)AWSLogs/\(self.accountID!)/CloudTrail-Digest/\(region)/"
                
                
                guard let allFiles = self.allFilesInDirectory(path: regionPath) else {
                    self.failAbilityToAudit(reason: "Could not find region directory structure.")
                    return
                }
                
                guard let recentFiles = self.allFilesInDirectory(path: endDatePath) else {
                    self.failAbilityToAudit(reason: "Could not find region directory structure.")
                    return
                }
                
                if recentFiles.count == 0 {
                    self.failAbilityToAudit(reason: "No digests found - error with download?")
                    return
                }
                
                var firstDigestInChain = recentFiles.first
                
                self.processDigestsTask.numberOfSubtasks += allFiles.count
                
                firstDigestInChain = firstDigestInChain?.replacingOccurrences(of: self.rootFolderPath, with: "")
                firstDigestInChain = "AWSLogs/\(self.accountID!)/CloudTrail-Digest/\(region)/\(year)/\(String(format: "%02d", month))/\(String(format: "%02d", day))/\(firstDigestInChain!)"
                
                var rootSignatureCompleted = false
                var regionRootSignature : RegionRootSignature? = nil
                self.getMetadataSignature(forKey: firstDigestInChain!, completion: { signature in
                    if let sig = signature {
                        regionRootSignature = RegionRootSignature(region: region, signature: sig)
                        self.rootSignatures.append(regionRootSignature!)
                        print("returned here for region \(region)")
                    }
                    else {
                        self.failAbilityToAudit(reason: "Failed to get signature for \(firstDigestInChain!)")
                        return
                    }
                    rootSignatureCompleted = true
                })
                
                while !rootSignatureCompleted {
                    sleep(1)
                    if self.didFailAbilityToAudit() { return }
                }
                
                //print("Finished here for region \(region), \(firstDigestInChain)")
                self.digestQueue.addOperation {
                    if self.didFailAbilityToAudit() {return}
                    self.processDigestChain(region: region, firstDigestInChain: firstDigestInChain!, rsaSignature: (regionRootSignature?.signature)!, isRoot: true)
                }
            }
        }
        setupDigestProcessingQueue.waitUntilAllOperationsAreFinished()
        self.updateEstimatedPercentComplete()
        
//        for region in regions {
//            setupDigestProcessingQueue.addOperation {
//                var didCompleteCall = false
//                CloudTrailService.getPublicKeys(credentialsProvider: self.credentialsProvider!, region: region, completion: { regionKeys in
//                    print("Received keys \(region) : \(regionKeys.count)")
//                    self.publicKeys.append(contentsOf: regionKeys)
//                    didCompleteCall = true
//                })
//
//                while !didCompleteCall {
//                    sleep(1)
//                    if self.didFailAbilityToAudit() { return }
//                }
//            }
//        }
        
        // read public keys from file, since there is a bug with AWS API list-public-keys
        // this was prepopulated with (and can be validated with) AWS CLI:
        // aws cloudtrail list-public-keys --start-time 2018-06-01T20:30:00.000Z --region "us-west-2"
        if let filepath = Bundle.main.path(forResource: "PublicKeys", ofType: "json") {
            do {
                let contents = try String(contentsOfFile: filepath)
                let json = try JSONSerialization.jsonObject(with: contents.data(using: .utf8)!, options: [])
                if let object = json as? [String: Any] {
                    for (region, publicKeyArray) in object {
                        for item in publicKeyArray as! [Dictionary<String, AnyObject>] {
                            publicKeys.append(PublicKey(region: region, key: item["Value"] as! String, fingerprint: item["Fingerprint"] as! String))
                        }
                    }
                } else {
                    print("JSON is not expected format")
                }
            } catch {
                print("Public Key file couldn't be parsed")
            }
        } else {
            print("Public Key file not found")
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
        awsDateFormat.locale = Locale(identifier: "en_US_POSIX")
        awsDateFormat.calendar = Calendar.init(identifier: .iso8601)
        
        awsDateFormat.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        let stringGivenDate = awsDateFormat.date(from: digestEndTime!)
        let timeSinceNow = Int((stringGivenDate?.timeIntervalSinceNow)!)
        
        //find the oldest set of logs for a region (worst case for how outdated the logs are)
        if abs(furthestStartLog) < abs(timeSinceNow) {
            furthestStartLog = abs(timeSinceNow)
        }

    }
    
    private func validateLogOrRedownload(logPath : String) {
        for _ in 0...100 {
            let gzipURL = URL.init(fileURLWithPath: logPath)
            if let content = try? Data(contentsOf: gzipURL), let gzipContent = content.isGzipped ? try? content.gunzipped() : content {
                if let zipCall = try? JSONDecoder().decode(Records.self, from: gzipContent) {
                    return //could decode into Record
                }
            }
            
            //if reached, try to re-download
            let output = URL.init(fileURLWithPath: logPath)
            if let startIndex = logPath.range(of: "AWSLogs/")?.lowerBound {
                print("Trying to recover by downloading")
                let key = String(logPath[startIndex...])
                (s3Sync?.downloadFile(key: key, outputURL: output))!
            }
            else {
                return
            }
            sleep(5)
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
                    validateLogOrRedownload(logPath: logFilePath)
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
        
        let fingerprint = digest.digestPublicKeyFingerprint
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
            print("Failed RSA signature verification for \(fullPath)")
            print("Using backup verification method: Checking signature on S3.")
            self.getMetadataSignature(forKey: s3Object, completion: { signature in
                if let sig = signature {
                    let result2 = Utils.verifyBytesSHA256withRSA(inputData: dataSigningString.data(using: .utf8)!, signature: sig.dataFromHexString()!, publicKey: seckey!)
                    if (!result2) {
                        self.violations.append(Violation(name: "Corrupted Trail File", eventTime: nil, eventName: nil, awsRegion: nil, sourceIP: nil, filePath:fullPath))
                    }
                    else {
                        print("S3 signature check succeeded")
                    }
                }
                else {
                    self.violations.append(Violation(name: "Corrupted Trail File, S3 Head Failed", eventTime: nil, eventName: nil, awsRegion: nil, sourceIP: nil, filePath:fullPath))
                    self.failAbilityToAudit(reason: "Failed to get signature from s3 for \(s3Object)")
                    return
                }
            })
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
        awsDateFormat.locale = Locale(identifier: "en_US_POSIX")
        awsDateFormat.calendar = Calendar.init(identifier: .iso8601)
        
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
                
                let output = URL.init(fileURLWithPath: fullPath)
                if let startIndex = fullPath.range(of: "AWSLogs/")?.lowerBound {
                    print("Trying to recover by downloading")
                    let key = String(fullPath[startIndex...])
                    
                    var success = false
                    for _ in 0...100 {
                        success = (s3Sync?.downloadFile(key: key, outputURL: output))!
                        
                        if success {
                            if let content = try? Data(contentsOf: gzipURL), let gzipContent = content.isGzipped ? try? content.gunzipped() : content {
                                if let zipCall = try? JSONDecoder().decode(Records.self, from: gzipContent) {
                                    for (index, awsCall) in zipCall.records.enumerated() {
                                        processAWSCall(logFilePath:fullPath, awsCall: awsCall)
                                    }
                                    break
                                }
                            }
                        }
                        sleep(5)
                    }
                    
                    if !success {
                        violations.append(Violation(name: "Couldn't load record", eventTime: nil, eventName: nil, awsRegion: nil, sourceIP: nil, filePath:fullPath))
                    }
                    
                }
                else {
                    violations.append(Violation(name: "Couldn't load record", eventTime: nil, eventName: nil, awsRegion: nil, sourceIP: nil, filePath:fullPath))
                }
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
        // EC2 SSH check
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
        // Lightsail SSH check
        if awsCall.eventSource == "lightsail.amazonaws.com" && awsCall.eventName == "CreateInstances" {
            guard let userData = awsCall.requestParameters?.userData else {
                let vio = Violation.init(name: "No UserData on Lightsail bringup",
                                         eventTime: awsCall.eventTime,
                                         eventName: awsCall.eventName,
                                         awsRegion: awsCall.awsRegion,
                                         sourceIP: awsCall.sourceIPAddress,
                                         filePath: logFilePath)
                violations.append(vio)
                return
            }
            if (userData.contains("rm /home/ubuntu/.ssh/authorized_keys") &&
                userData.contains("rm /root/.ssh/authorized_keys") &&
                userData.contains("systemctl disable ssh.service") &&
                userData.contains("systemctl stop ssh.service")) {
                return
            }
            else {
                let vio = Violation.init(name: "Lightsail disable SSH not detected",
                                         eventTime: awsCall.eventTime,
                                         eventName: awsCall.eventName,
                                         awsRegion: awsCall.awsRegion,
                                         sourceIP: awsCall.sourceIPAddress,
                                         filePath: logFilePath)
                violations.append(vio)
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
            // don't count loggroup deletions performed by CloudFormation (not done by operator)
            if (awsCall.sourceIPAddress != "cloudformation.amazonaws.com") {
                let vio = Violation.init(name: "LogGroup/LogStream Deleted",
                                         eventTime: awsCall.eventTime,
                                         eventName: awsCall.eventName,
                                         awsRegion: awsCall.awsRegion,
                                         sourceIP: awsCall.sourceIPAddress,
                                         filePath:logFilePath)
                violations.append(vio)
            }
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
    var downloadQueueAltProcessingQueue = OperationQueue.init()
    var downloadQueueAltProcessingQueue2 = OperationQueue.init()
    var downloadQueueAltProcessingQueue3 = OperationQueue.init()
    var downloadQueueAltProcessingQueue4 = OperationQueue.init()
    
    var s3Sync : S3Sync?
    
    var getParametersState = NSButton.StateValue.on
    var safeBringupState = NSButton.StateValue.on
    var roleState = NSButton.StateValue.on
    var sshState = NSButton.StateValue.on
    var flowLogState = NSButton.StateValue.on
    var runCommandState = NSButton.StateValue.on
    var deleteLogsState = NSButton.StateValue.on
    var credentialsProvider : AWSStaticCredentialsProvider? = nil
    var defaultServiceConfiguration : AWSServiceConfiguration?
    var endpoint : AWSEndpoint?
    
    var furthestStartLog : Int = 0
    
    var accountID : String? = nil //need to fetch this from AWS in the future
    //if changing account ID, also have to change endpoint AWSRegionType in init of engine
    
    static var sessionKey : Int = 0
    
    static let supportedRegions = ["ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", /*"eu-west-3",*/ "sa-east-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2"]
    
}

