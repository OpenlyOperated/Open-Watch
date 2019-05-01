//
//  CloudTrailService.swift
//  OpenWatch
//
//  Created by Confirmed, Inc. on 11/14/18.
//  Copyright © 2018 Confirmed, Inc. All rights reserved.
//

import Cocoa
import AWSCore
import AWSS3
import Alamofire
import SWXMLHash

class CloudTrailService: AWSService {

    static let endPointURL = "https://cloudtrail.us-west-1.amazonaws.com"
    /*
        * this must be called after S3Sync sets up credentials
     */
    static func getCloudTrailBucket(credentialsProvider : AWSStaticCredentialsProvider, completion: @escaping (_ bucketName: String?) -> Void) -> Void {
        let endPoint = AWSEndpoint(region: AWSRegionType.USWest1, service: AWSServiceType.cloudTrail, url: URL.init(string: endPointURL))
        let signer = AWSSignatureV4Signer(credentialsProvider: credentialsProvider, endpoint:endPoint)
        let request = NSMutableURLRequest(url: NSURL(string: "\(endPointURL)/?Action=DescribeTrails")! as URL)
        
        request.setValue(NSDate.init().aws_stringValue(AWSDateISO8601DateFormat2), forHTTPHeaderField: "X-Amz-Date")
        
        var processedXML = false
        signer?.interceptRequest(request).continue({ task in
            
            print("Tasking \(request.allHTTPHeaderFields)")
            
            do {
                // Perform the request
                var response: AutoreleasingUnsafeMutablePointer<URLResponse?>? = nil
                let data = try NSURLConnection.sendSynchronousRequest(request as URLRequest, returning: response)
                
                var str = String(data: data, encoding: String.Encoding.utf8) as String!
                
                let xml = SWXMLHash.config {
                    config in
                    config.shouldProcessLazily = true
                    }.parse(str!)
                
                let bucketName = xml["DescribeTrailsResponse"]["DescribeTrailsResult"]["trailList"]["member"][0]["S3BucketName"].element?.text
                print("Str \(bucketName)")
                completion(bucketName)
                processedXML = true
            } catch {
                processedXML = true
                completion(nil)
            }
            
            return nil
        })
        
        //force the call to be synchronous
        while !processedXML {
            sleep(1)
        }
    }
    
    static func getTypeFromRegion(region : String) -> AWSRegionType {
        
        if region == "us-west-1" {
            return AWSRegionType.USWest1
        } else if region == "us-west-2" {
            return AWSRegionType.USWest2
        } else if region == "us-east-1" {
            return AWSRegionType.USEast1
        } else if region == "us-east-2" {
            return AWSRegionType.USEast2
        } else if region == "ca-central-1" {
            return AWSRegionType.CACentral1
        } else if region == "eu-west-1" {
            return AWSRegionType.EUWest1
        } else if region == "eu-west-2" {
            return AWSRegionType.EUWest2
        } else if region == "eu-west-3" {
            return AWSRegionType.EUWest3
        } else if region == "eu-central-1" {
            return AWSRegionType.EUCentral1
        } else if region == "ap-southeast-1" {
            return AWSRegionType.APSoutheast1
        } else if region == "ap-southeast-2" {
            return AWSRegionType.APSoutheast2
        } else if region == "ap-northeast-1" {
            return AWSRegionType.APNortheast1
        } else if region == "ap-northeast-2" {
            return AWSRegionType.APNortheast2
        } else if region == "ap-northeast-3" {
            return AWSRegionType.APNortheast3
        } else if region == "sa-east-1" {
            return AWSRegionType.SAEast1
        } else if region == "ap-south-1" {
            return AWSRegionType.APSouth1
        }
        
        return AWSRegionType.USWest1
    }
    
    static func getAccountID(credentialsProvider : AWSStaticCredentialsProvider, region: String, completion: @escaping (_ accountID: String?) -> Void) -> Void {
        
        let publicKeyEndpoint = "https://sts.\(region).amazonaws.com"
        
        let regionType = getTypeFromRegion(region: region)
        let endPoint = AWSEndpoint(region: regionType, service: AWSServiceType.STS, url: URL.init(string: publicKeyEndpoint))
        let signer = AWSSignatureV4Signer(credentialsProvider: credentialsProvider, endpoint:endPoint)
        let request = NSMutableURLRequest(url: NSURL(string: "\(publicKeyEndpoint)")! as URL)
        
        request.setValue(NSDate.init().aws_stringValue(AWSDateISO8601DateFormat2), forHTTPHeaderField: "X-Amz-Date")
        var body: [String: String] = [:]
        body = ["Action": "GetCallerIdentity", "Version": "2011-06-15"]
        request.httpBody = body.map{"\($0)=\($1)"}.joined(separator: "&").data(using: .utf8)
        request.httpMethod = "POST"
        signer?.interceptRequest(request).continue({ task in
            
            print("Tasking \(request.allHTTPHeaderFields)")
            
            do {
                // Perform the request
                var response: AutoreleasingUnsafeMutablePointer<URLResponse?>? = nil
                let data = try NSURLConnection.sendSynchronousRequest(request as URLRequest, returning: response)
                
                
                var str = String(data: data, encoding: String.Encoding.utf8) as String!
                
                let xml = SWXMLHash.parse(str!)
                
                var publicKeys = [PublicKey]()
                let accountID = xml["GetCallerIdentityResponse"]["GetCallerIdentityResult"]["Account"].element?.text
                
                completion(accountID)
            } catch {
                print("Couldn't find Account ID")
                completion(nil)
            }
            
            return nil
        })
        
    }
    
    static func getPublicKeys(credentialsProvider : AWSStaticCredentialsProvider, region: String, completion: @escaping (_ publicKeys: [PublicKey]) -> Void) -> Void {
        let publicKeyEndpoint = "https://cloudtrail.\(region).amazonaws.com"
        
        let startTime = "2018-11-01T20%3A30%3A00.000Z"
        let regionType = getTypeFromRegion(region: region)
        let endPoint = AWSEndpoint(region: regionType, service: AWSServiceType.cloudTrail, url: URL.init(string: publicKeyEndpoint))
        let signer = AWSSignatureV4Signer(credentialsProvider: credentialsProvider, endpoint:endPoint)
        let request = NSMutableURLRequest(url: NSURL(string: "\(publicKeyEndpoint)/?Action=ListPublicKeys&StartTime=\(startTime)")! as URL)
        
        request.setValue(NSDate.init().aws_stringValue(AWSDateISO8601DateFormat2), forHTTPHeaderField: "X-Amz-Date")
        
        signer?.interceptRequest(request).continue({ task in
            
            print("Tasking \(request.allHTTPHeaderFields)")
            
            do {
                // Perform the request
                var response: AutoreleasingUnsafeMutablePointer<URLResponse?>? = nil
                let data = try NSURLConnection.sendSynchronousRequest(request as URLRequest, returning: response)
                
                
                var str = String(data: data, encoding: String.Encoding.utf8) as String!
                
                let xml = SWXMLHash.parse(str!)
                
                var publicKeys = [PublicKey]()
                for elem in xml["ListPublicKeysResponse"]["ListPublicKeysResult"]["PublicKeyList"]["member"].all {
                    publicKeys.append(PublicKey(region: region, key: elem["Value"].element?.text, fingerprint: elem["Fingerprint"].element?.text))
                }
                
                completion(publicKeys)
            } catch {
            }
            
            return nil
        })
    }
    
}

