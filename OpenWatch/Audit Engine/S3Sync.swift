//
//  S3Sync.swift
//  OpenWatch
//
//

import Cocoa
import AWSCore
import AWSS3

class S3Sync: NSObject {

    init(credentialsProvider: AWSCredentialsProvider,
         accountID : String,
         bucket : String,
         endpoint : AWSEndpoint,
         downloadDirectory : String,
         startDate : Date,
         endDate : Date
        ) {
        self.credentials = credentialsProvider
        self.accountID = accountID
        self.downloadDirectory = downloadDirectory
        self.endpoint = endpoint
        self.bucket = bucket
        self.startDate = startDate
        self.endDate = endDate
        self.accessKey = credentialsProvider.accessKey!!
        self.secretKey = credentialsProvider.secretKey!!
    }
    
    func findAndDownloadAllFiles(progressUpdateCallback: @escaping (
        _ calculateTotalDownloadTasks : Int,
        _ completedCalculateTotalDownloadTasks : Int,
        _ totalDownloadTasks : Int,
        _ completedDownloadTasks : Int,
        _ errorMessage : String?
        ) -> Void) -> Void {
        
        var currentProcessedDate = startDate
        var logFiles = [AWSS3Object]()
        var digestFiles = [AWSS3Object]()
        
        //remove old tmp folder
        let fileManager = FileManager.default
        do {
            try fileManager.removeItem(atPath: self.downloadDirectory)
        }
        catch let error as NSError {
            print("Could not delete folder: \(error)")
        }
        
        //start at 1, the parent task to set up async calls
        var calculateDownloadTasks = 1
        var completedCalculateDownloadTasks = 0
        
        progressUpdateCallback(calculateDownloadTasks, completedCalculateDownloadTasks, 1, 0, nil)
        downloadQueueProcessingQueue.maxConcurrentOperationCount = 2 //limit to 2 because of AWS API limits
        
        while currentProcessedDate.timeIntervalSince(endDate) < 86399.999999 { //get up to 1 day ahead for time zones
            let calendar = Calendar.current
            
            let year = calendar.component(.year, from: currentProcessedDate)
            let month = calendar.component(.month, from: currentProcessedDate)
            let day = calendar.component(.day, from: currentProcessedDate)
            
            for region in OpenWatchEngine.supportedRegions {
                
                calculateDownloadTasks += 2 //one for logs, one for digest
                progressUpdateCallback(calculateDownloadTasks, completedCalculateDownloadTasks, 1, 0, nil)
                
                let prefixLogs = "AWSLogs/\(self.accountID)/CloudTrail/\(region)/\(year)/\(String(format: "%02d", month))/\(String(format: "%02d", day))"
                let prefixDigest = "AWSLogs/\(self.accountID)/CloudTrail-Digest/\(region)/\(year)/\(String(format: "%02d", month))/\(String(format: "%02d", day))"
                
                downloadQueueProcessingQueue.addOperation {
                    autoreleasepool {
                        var completedTask = false
                        self.getAllFilesFromS3(prefix: prefixLogs, marker: nil, result: { keys in
                            //print("Log Prefix: \(prefixLogs) Log Keys: \(keys.count)")
                            Utils.synced(self, closure: {
                                logFiles.append(contentsOf: keys)
                                completedCalculateDownloadTasks += 1
                            })
                            
                            progressUpdateCallback(calculateDownloadTasks, completedCalculateDownloadTasks, 1, 0, nil)
                            
                            completedTask = true
                        })
                        
                        while(!completedTask) {
                            usleep(250000)
                        }
                    }
                }
                
                downloadQueueProcessingQueue.addOperation {
                    autoreleasepool {
                        var completedTask = false
                        self.getAllFilesFromS3(prefix: prefixDigest, marker: nil, result: { keys in
                            //print("Prefix: \(prefixLogs) Digest Keys: \(keys.count)")
                            Utils.synced(self, closure: {
                                digestFiles.append(contentsOf: keys)
                                completedCalculateDownloadTasks += 1
                            })
                            progressUpdateCallback(calculateDownloadTasks, completedCalculateDownloadTasks, 1, 0, nil)
                            
                            completedTask = true
                        })
                        while(!completedTask) {
                            usleep(250000)
                        }
                    }
                }
                
            }
            
            currentProcessedDate = Calendar.current.date(byAdding: .day, value: 1, to: currentProcessedDate)!
            //print("Time interval here \(currentProcessedDate.timeIntervalSince(self.endDate))")
        }
        
        
        sleep(5)
        downloadQueueProcessingQueue.waitUntilAllOperationsAreFinished()
        
        completedCalculateDownloadTasks += 1
        progressUpdateCallback(calculateDownloadTasks, completedCalculateDownloadTasks, 1, 0, nil)
        
        while(completedCalculateDownloadTasks < calculateDownloadTasks) {
            sleep(1)
            if shouldEndS3Sync { return }
        }
        
        
        print("Downloading all files - \(logFiles.count)")
        print("Downloading all digests - \(digestFiles.count)")
        
        logFiles.append(contentsOf: digestFiles)
        
        let downloadTasks = logFiles.count
        var completedDownloadTasks = 0
        progressUpdateCallback(calculateDownloadTasks, calculateDownloadTasks, downloadTasks, completedDownloadTasks, nil)
        
        //now download the files into a folder
        DispatchQueue.concurrentPerform(iterations: logFiles.count) { (index) in
            autoreleasepool {
                let obj = logFiles[index]
                let outputDirectory = "\(self.downloadDirectory)\(Utils.stripFileComponent(obj.key!))"
                let outputPath = "\(self.downloadDirectory)/\(obj.key!)"
                let outputURL = URL.init(fileURLWithPath: outputPath)
                
                do {
                    if !FileManager.default.fileExists(atPath: outputDirectory) {
                        try FileManager.default.createDirectory(atPath: outputDirectory, withIntermediateDirectories: true, attributes: nil)
                    }
                }
                catch let error as NSError {
                    NSLog("Unable to create directory \(error.debugDescription)")
                }
                
                autoreleasepool {
                    self.downloadFile(key: obj.key, outputURL: outputURL)
                }
                
                Utils.synced(self, closure: {
                    completedDownloadTasks += 1
                })
                
                if arc4random_uniform(2) == 1 {
                    progressUpdateCallback(calculateDownloadTasks, calculateDownloadTasks, downloadTasks, completedDownloadTasks, nil)
                }
            }
        }
        
        sleep(5)
        if logFiles.count == 0 || digestFiles.count == 0 {
            progressUpdateCallback(calculateDownloadTasks, calculateDownloadTasks, downloadTasks, completedDownloadTasks, "No logs or digests (Is CloudTrail Region correct?)")
            return
        }
        while(completedDownloadTasks < downloadTasks) {
            sleep(1)
            if shouldEndS3Sync { return }
        }
        
        while erroredFiles.keys.count > 0 {
            for (key, value) in erroredFiles {
                print("Retrying failed download...")
                let didSucceed = self.downloadFile(key: key, outputURL: value)
                if didSucceed {
                    erroredFiles.removeValue(forKey: key)
                }
                else {
                    print("Retrying failed download...")
                }
                usleep(250000)
            }
        }
        
        print("Downloaded everything")
        progressUpdateCallback(calculateDownloadTasks, calculateDownloadTasks, downloadTasks, completedDownloadTasks, nil)
        
    }
    
    func getAllFilesFromS3(prefix : String?, marker: String?, result: @escaping (_ keys: [AWSS3Object]) -> Void) {
        let s3 = AWSS3.s3(forKey: "\(OpenWatchEngine.sessionKey)")
        
        let objReq = AWSS3ListObjectsRequest.init()
        objReq?.bucket = self.bucket
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
    
    func generateQueryStringForSignatureV4(
        keyName : String,
        httpMethod : AWSHTTPMethod,
        contentType : String?,
        expireDuration : Int,
        requestParameters : Dictionary<String, Any>,
        keyPath : String,
        host : String,
        contentMD5 : String?,
        sessionKey : String?
        ) -> NSMutableString {
        //Implementation of V4 signaure http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
        let queryString = NSMutableString.init()
        
        //Append Identifies the version of AWS Signature and the algorithm that you used to calculate the signature.
        queryString.appendFormat("%@=%@&","X-Amz-Algorithm",AWSSignatureV4Algorithm)
        
        //Get ClockSkew Fixed Date
        let currentDate : NSDate = NSDate.aws_clockSkewFixed()! as NSDate
        
        //Format of X-Amz-Credential : <your-access-key-id>/<date>/<AWS-region>/<AWS-service>/aws4_request.
        let scope = NSString.init(format:"%@/%@/%@/%@",
                                  currentDate.aws_stringValue("yyyyMMdd"),
                                  endpoint.regionName,
                                  endpoint.serviceName,
                                  AWSSignatureV4Terminator);
        
        
        let signingCredentials = NSString.init(format: "%@/%@", self.accessKey, scope)
        
        //need to replace "/" with "%2F"
        let xAmzCredentialString = signingCredentials.replacingOccurrences(of: "/", with: "%2F")
        
        queryString.appendFormat("%@=%@&", "X-Amz-Credential", xAmzCredentialString)
        
        
        //X-Amz-Date in ISO 8601 format, for example, 20130721T201207Z. This value must match the date value used to calculate the signature.
        queryString.appendFormat("%@=%@&", "X-Amz-Date", currentDate.aws_stringValue(AWSDateISO8601DateFormat2))
        
        
        //X-Amz-Expires, Provides the time period, in seconds, for which the generated presigned URL is valid.
        //For example, 86400 (24 hours). This value is an integer. The minimum value you can set is 1, and the maximum is 604800 (seven days).
        queryString.appendFormat("%@=%d&", "X-Amz-Expires", expireDuration);
        
        
        /*
         X-Amz-SignedHeaders Lists the headers that you used to calculate the signature. The HTTP host header is required.
         Any x-amz-* headers that you plan to add to the request are also required for signature calculation.
         In general, for added security, you should sign all the request headers that you plan to include in your request.
         */
        
        let headers = NSMutableDictionary.init()
        let key : NSString = "host"
        headers.setObject(host, forKey: key)
        
        
        if let cType = contentType, cType.count > 0 {
            let contentKey : NSString = "Content-Type"
            headers.setObject(cType, forKey: contentKey)
        }
        if let cType = contentMD5, cType.count > 0 {
            let md5Key : NSString = "Content-MD5"
            headers.setObject(cType, forKey: md5Key)
        }
        
        AWSSignatureV4Signer.getSignedHeadersString(headers as! [AnyHashable : Any]).aws_stringWithURLEncoding()
        
    queryString.appendFormat("%@=%@&","X-Amz-SignedHeaders",AWSSignatureV4Signer.getSignedHeadersString(headers as! [AnyHashable : Any]).aws_stringWithURLEncoding())
        
        
        //add additionalParameters to queryString
        for (key, value) in requestParameters {
            if value is NSNull {
                queryString.appendFormat("%@=&",key.aws_stringWithURLEncoding());
            } else {
                queryString.appendFormat("%@=%@&",key.aws_stringWithURLEncoding(), (value as AnyObject).aws_stringWithURLEncoding());
            }
            
        }
        
        //add security-token if necessary
        if sessionKey != nil, sessionKey!.count > 0 {
            queryString.appendFormat("%@=%@&", "x-amz-security-token", (sessionKey!.aws_stringWithURLEncoding())!);
        }
        
        
        // =============  generate v4 signature string ===================
        
        /* Canonical Request Format:
         *
         * HTTP-VERB + "\n" +  (e.g. GET, PUT, POST)
         * Canonical URI + "\n" + (e.g. /test.txt)
         * Canonical Query String + "\n" (multiple queryString need to sorted by QueryParameter)
         * Canonical Headrs + "\n" + (multiple headers need to be sorted by HeaderName)
         * Signed Headers + "\n" + (multiple headers need to be sorted by HeaderName)
         * "UNSIGNED-PAYLOAD"
         */
        
        
        let httpMethodString = NSString.aws_string(with: httpMethod)
        
        
        //CanonicalURI is the URI-encoded version of the absolute path component of the URI—everything starting with the "/" that follows the domain name and up to the end of the string or to the question mark character ('?') if you have query string parameters. e.g. https://s3.amazonaws.com/examplebucket/myphoto.jpg /examplebucket/myphoto.jpg is the absolute path. In the absolute path, you don't encode the "/".
        let canonicalURI = NSString.init(format:"/%@",keyPath) //keyPath has already been url-encoded.
        
        let contentSha256 = "UNSIGNED-PAYLOAD"
        
        
        //Generate Canonical Request
        let canonicalRequest = AWSSignatureV4Signer.getCanonicalizedRequest(httpMethodString as String?,
                                                                            path:canonicalURI as String,
                                                                            query:queryString as String,
                                                                            headers:headers as! [AnyHashable : Any],
                                                                            contentSha256:contentSha256)
        //AWSLogDebug(@"AWSS4 PresignedURL Canonical request: [%@]", canonicalRequest);
        
        
        //Generate String to Sign
        let stringToSign = NSString.init(format: "%@\n%@\n%@\n%@",
                                         AWSSignatureV4Algorithm,
                                         currentDate.aws_stringValue(AWSDateISO8601DateFormat2),
                                         scope,
            AWSSignatureSignerUtility.hexEncode(AWSSignatureSignerUtility.hashString(canonicalRequest)))
        
        
        //Generate Signature
        let kSigning  = AWSSignatureV4Signer.getV4DerivedKey(
            self.secretKey,
            date:currentDate.aws_stringValue(AWSDateShortDateFormat1),
            region:endpoint.regionName,
            service:endpoint.serviceName);
        
        let signature = AWSSignatureSignerUtility.sha256HMac(with: stringToSign.data(using:String.Encoding.utf8.rawValue),
                                                             withKey:kSigning);
        let signatureString = AWSSignatureSignerUtility.hexEncode(NSString.init(data: signature!, encoding: String.Encoding.ascii.rawValue) as String?)
        
        
        // ============  generate v4 signature string (END) ===================
        
        queryString.appendFormat("%@=%@","X-Amz-Signature",signatureString!);
        
        return queryString
        
    }
    
    
    func getPresignedURL(getPreSignedURLRequest : AWSS3GetPreSignedURLRequest, credentials: AWSCredentialsProvider, keyName : String, expires : Date, httpMethod : AWSHTTPMethod, contentType : String?, contentMD5 : String?) -> NSURL? {
        
        
        for (key, value) in getPreSignedURLRequest.requestParameters {
            if key is NSString || (value is NSString && value is NSNull) {
                return nil;
                //"requestParameters can only contain key-value pairs in NSString type."
            }
        }
        
        
        
        //validate keyName
        if keyName.count < 1 {
            return nil;
        }
        
        //validate expires Date
        if expires.timeIntervalSinceNow < 0.0 {
            return nil;
        }
        
        if httpMethod == .GET || httpMethod == .PUT || httpMethod == .HEAD || httpMethod == .DELETE { }
        else {
            return nil;
        }
        
        //validate expiration date if using temporary token and refresh it if condition met
        if let expiration = credentials.expiration, expiration!.timeIntervalSinceNow < getPreSignedURLRequest.minimumCredentialsExpirationInterval {
            credentials.refresh?()
        }
        
        //validate accessKey
        if self.accessKey.count < 1 {
            return nil;
            //@"accessKey in credentialsProvider can not be nil"
        }
        
        if self.secretKey.count < 1  {
            return nil;
            //@"secretKey in credentialsProvider can not be nil"
        }
        
        
        //generate baseURL String (use virtualHostStyle if possible)
        var keyPath : NSString;
        
        if (self.bucket.aws_isVirtualHostedStyleCompliant()) {
            keyPath = (keyName == nil ? "" : NSString.init(format: "%@", keyName.aws_stringWithURLEncodingPath()))
        } else {
            keyPath = (keyName == nil ? "" : NSString.init(format: "%@/%@", self.bucket, keyName.aws_stringWithURLEncodingPath()))
        }
        
        var host : String;
        if (self.bucket.aws_isVirtualHostedStyleCompliant()) {
            host = String.init(format:"%@.%@", self.bucket, endpoint.hostName);
        } else {
            host = endpoint.hostName;
        }
        
        var expireDuration = expires.timeIntervalSinceNow
        
        if expireDuration > 604800 {
            return nil;
            //"Invalid ExpiresDate, must be less than seven days in future"}]
        }
        
        let sessionKey = credentials.sessionKey
        guard let accessKey = credentials.accessKey, let secretKey = credentials.secretKey else {
            return nil
        }
        
        let generatedQueryString = self.generateQueryStringForSignatureV4(
            keyName: keyName,
            httpMethod: httpMethod,
            contentType: contentType,
            expireDuration: Int(expireDuration),
            requestParameters: getPreSignedURLRequest.requestParameters as! Dictionary<String, Any>,
            keyPath: keyPath as String,
            host: host,
            contentMD5: contentMD5,
            sessionKey: sessionKey ?? nil
        )
        
        
        let urlString = NSString.init(format:"%@://%@/%@?%@", endpoint.useUnsafeURL ? "http":"https", host, keyPath, generatedQueryString);
        let result = NSURL.init(string:urlString as String);
        
        return result
    }
    
    func downloadFile(key : String, outputURL : URL) -> Bool {
        let getPreSignedURLRequest = AWSS3GetPreSignedURLRequest.init()
        getPreSignedURLRequest.bucket = bucket;
        getPreSignedURLRequest.key = key;
        getPreSignedURLRequest.httpMethod = .GET
        getPreSignedURLRequest.expires = Date.init(timeIntervalSinceNow: 50 * 60)
        
        let keyName = getPreSignedURLRequest.key;
        let httpMethod = getPreSignedURLRequest.httpMethod;
        
        let expires = getPreSignedURLRequest.expires!;
        
        let contentType = getPreSignedURLRequest.contentType;
        let contentMD5 = getPreSignedURLRequest.contentMD5;
        
        guard let presignedURL = self.getPresignedURL(getPreSignedURLRequest: getPreSignedURLRequest, credentials: credentials, keyName: keyName!, expires: expires, httpMethod: httpMethod, contentType: contentType, contentMD5: contentMD5) else {
            print("Failed to get pre-signed URL")
            return false
        }
        
        var didRequestSucceed = false;
        autoreleasepool {
            let request = NSMutableURLRequest.init(url: presignedURL as URL)
            request.cachePolicy = .reloadIgnoringLocalCacheData;
            request.httpMethod = "GET";
            
            request.setValue(NSString.aws_baseUserAgent(), forHTTPHeaderField:"User-Agent");
            let session = URLSession.shared
            
            let task = session.dataTask(with: request as URLRequest, completionHandler: { data, response, error in
                
                if error != nil || data == nil {
                    self.erroredFiles[key] = outputURL
                    return
                }
                
                
                do {
                    try data!.write(to: outputURL)
                    didRequestSucceed = true
                } catch let error {
                    print(error.localizedDescription)
                    self.erroredFiles[key] = outputURL
                }
            })
            
            task.resume()
            while task.state == .running {
                usleep(5000)
            }
        }
        
        return didRequestSucceed
    }
    
    //MARK: - VARIABLES
    
    var accountID : String
    var downloadDirectory : String
    var bucket : String
    var credentials : AWSCredentialsProvider
    var accessKey : String
    var secretKey : String
    var endpoint : AWSEndpoint
    var startDate : Date
    var endDate : Date
    
    var erroredFiles = [String : URL]()
    var downloadQueueProcessingQueue = OperationQueue.init()
    var shouldEndS3Sync = false
    
}
