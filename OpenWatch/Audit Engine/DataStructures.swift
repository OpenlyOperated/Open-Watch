//
//  APICall.swift
//  OpenWatch
//
//  Created by Confirmed, Inc. on 11/8/18.
//  Copyright © 2018 Confirmed, Inc. All rights reserved.
//

import Foundation
import SWXMLHash


//MARK: - RSA Signing
struct PublicKey {
    var region: String?
    var key: String?
    var fingerprint: String?
}

struct RegionRootSignature {
    var region: String
    var signature: String
}

//MARK: - OpenWatch Structures
struct Violation: Codable {
    let name: String?
    let eventTime: String?
    let eventName: String?
    let awsRegion: String?
    let sourceIP: String?
    let filePath: String?
    
}

class AuditTask {
    var tasks: [Task]?
    
    func currentTask() -> Task? {
        if tasks != nil {
            for task in tasks!  {
                if (!task.isFinished()) {
                    return task
                }
            }
        }
        
        return nil
    }
    func currentTaskNumber() -> Int {
        guard tasks != nil else { return 0 }
        return tasks!.index{$0 === currentTask()}!
    }
    /*
     * Audit can take quite a bit of time
     * Update caller appropriately so they know it is working
     * Download is the majority of time
     * Reweight if we are using S3 to download files
     * Call this method instead of progress update
     * Will call progress update after variables updated
     */
    func estimatePercentageComplete() -> Double {
        guard tasks != nil else { return 0.0 }
        
        
        var totalUnitsOfWork = 0
        var unitsCompleted = 0
        
        guard let currentTask = self.currentTask() else { return 0.0 }
        
        for task in tasks! {
            totalUnitsOfWork += task.estimatedUnitsOfWork
            if task.isFinished() {
                unitsCompleted += task.estimatedUnitsOfWork
            }
        }
        
        var currentTaskProgress = 0.0
        if !currentTask.isFinished() { //if it is finished, will be under units completed
            currentTaskProgress = Double(currentTask.estimatedUnitsOfWork * currentTask.completedSubtasks) / Double(currentTask.numberOfSubtasks)
        }
        
        return 100.0 * ((Double(unitsCompleted) + currentTaskProgress)
            / Double(totalUnitsOfWork))
    }
}

class Task {
    var taskName : String = ""
    var estimatedUnitsOfWork = 1 //can use this as a weighting
    var numberOfSubtasks = 0
    var completedSubtasks = 0
    
    func markAsFinished() {
        completedSubtasks = numberOfSubtasks
    }
    
    func isFinished() -> Bool {
        return numberOfSubtasks > 0 && completedSubtasks >= numberOfSubtasks
    }
    
    func resetTaskProgress() {
        numberOfSubtasks = 0
        completedSubtasks = 0
    }
}

//MARK: - AWS Records
struct Records: Codable {
    let records: [APICall]
    
    enum CodingKeys: String, CodingKey {
        case records = "Records"
    }
}

struct APICall: Codable {
    let eventSource: String?
    let eventTime: String?
    let eventName: String?
    let awsRegion: String?
    let sourceIPAddress: String?
    let eventID: String?
    let userIdentity: UserIdentity?
    let requestParameters: RequestParameters?
    
}


struct RequestParameters : Codable {
    let instancesSet: Items?
    let policyDocument: PolicyDocument?
    let assumeRolePolicyDocument: PolicyDocument?
    let applicationName: String?
    let revision: Revision?
    
    private enum CodingKeys: String, CodingKey {
        case instancesSet = "instancesSet"
        case policyDocument = "policyDocument"
        case assumeRolePolicyDocument = "assumeRolePolicyDocument"
        case applicationName = "applicationName"
        case revision = "revision"
    }
    
    //policy document is sometimes a string with escaped JSON
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        instancesSet = try values.decodeIfPresent(Items.self, forKey: .instancesSet)
        applicationName = try values.decodeIfPresent(String.self, forKey: .applicationName)
        revision = try values.decodeIfPresent(Revision.self, forKey: .revision)
        do {
            policyDocument = try values.decodeIfPresent(PolicyDocument.self, forKey: .policyDocument)
        }
        catch {
            let string = try values.decodeIfPresent(String.self, forKey: .policyDocument)?.replacingOccurrences(of: "\\\"", with: "\"").replacingOccurrences(of: "\n", with: "")
            let data = string!.data(using: .utf8)
            policyDocument = try JSONDecoder().decode(PolicyDocument.self, from: data!)
        }
        
        do {
            assumeRolePolicyDocument = try values.decodeIfPresent(PolicyDocument.self, forKey: .assumeRolePolicyDocument)
        }
        catch {
            let string = try values.decodeIfPresent(String.self, forKey: .assumeRolePolicyDocument)?.replacingOccurrences(of: "\\\"", with: "\"")
            let data = string!.data(using: .utf8)
            assumeRolePolicyDocument = try JSONDecoder().decode(PolicyDocument.self, from: data!)
        }
    }
}

struct Revision: Codable {
    let revisionType: String?
    let s3Location: S3Location?
}

struct S3Location: Codable {
    let key: String?
    let bucket: String?
    let version: String
}

struct PolicyDocument : Codable {
    let statement: [Statement]?
    var statementDictionary: StatementDictionary?
    
    enum CodingKeys: String, CodingKey {
        case statement = "Statement"
        case statementDictionary = "StatementDictionary"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        do {
            statement = try values.decodeIfPresent([Statement].self, forKey: .statement)
        }
        catch {
            statement = nil
            statementDictionary = nil
            do {
                statementDictionary = try values.decodeIfPresent(StatementDictionary.self, forKey: .statementDictionary)
            }
            catch {
                statementDictionary = nil
            }
        }
        
    }
}

struct Statement : Codable {
    let principal: Principal?
    let action: [String]?
    
    enum CodingKeys: String, CodingKey {
        case principal = "Principal"
        case action = "Action"
    }
}

struct StatementDictionary : Codable {
    let effect : String?
    
    enum CodingKeys: String, CodingKey {
        case effect = "Effect"
    }
}

struct Principal : Codable {
    let aws: String?
    let service: [String]?
    
    enum CodingKeys: String, CodingKey {
        case aws = "AWS"
        case service = "Service"
    }
}

struct Items : Codable {
    let items: [Item]?
}

struct Item : Codable {
    let imageId: String?
    let keyName: String?
}

struct UserIdentity : Codable {
    let type: String?
}


struct Digest : Codable {
    let digestS3Bucket : String?
    let digestS3Object : String?
    let digestEndTime : String?
    let digestPublicKeyFingerprint : String?
    let digestSignatureAlgorithm : String?
    let previousDigestS3Bucket : String?
    let previousDigestS3Object : String?
    let previousDigestHashValue : String?
    let previousDigestHashAlgorithm : String?
    let previousDigestSignature : String?
    let logFiles : [LogFile]?
}

struct LogFile : Codable {
    let s3Bucket : String?
    let s3Object : String?
    let hashValue : String?
    let hashAlgorithm : String?
}
