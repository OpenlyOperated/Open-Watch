//
//  ViewController.swift
//  OpenWatch
//
//  Created by Confirmed, Inc. on 11/8/18.
//  Copyright © 2018 Confirmed, Inc. All rights reserved.
//
// ICON - Glasses by Iris Sun from the Noun Project

import Cocoa
import Gzip
import DockProgress
import KeychainAccess

let keychain = Keychain(service: "com.confirmed.OpenWatch").synchronizable(true)
let kAWSSecret = "AWSSecret"
let kAWSKey = "AWSKey"
let kAWSRegion = "AWSRegion"

class ViewController: NSViewController, NSTableViewDelegate, NSTableViewDataSource {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.percentComplete?.stringValue = "0.0%"
        self.progressBar?.doubleValue = 0.0
        self.resultText?.stringValue = "Choose a source and click Analyze to begin."
        self.numberOfViolations?.stringValue = ""
        DockProgress.style = .circle(radius: 128, color: .systemBlue)
        
        startDate?.dateValue = Date.init(timeIntervalSinceNow: -600000) //default start date is about a week back
        startDate?.maxDate = Date.init(timeIntervalSinceNow: 0) //max date is today
        endDate?.dateValue = Date.init(timeIntervalSinceNow: 0) //default end date is today
        endDate?.maxDate = Date.init(timeIntervalSinceNow: 0)
        sourceURL?.stringValue = ""
        
        if let key = keychain[kAWSKey], let secret = keychain[kAWSSecret] {
            awsKey?.stringValue = key
            awsSecret?.stringValue = secret
        }
        
        if let region = keychain[kAWSRegion], let itemArray = self.awsRegion?.itemArray {
            for (index, item) in itemArray.enumerated() {
                if item.identifier?.rawValue == region {
                    self.awsRegion?.selectItem(at: index)
                }
            }
        }
        
        
    }
    
    @IBAction func startAnalyzing(sender : NSButton) {
        self.freezeUI()
        self.percentComplete?.stringValue = "0.0%"
        self.progressBar?.doubleValue = 0.0
        DockProgress.progressValue = 0.0
        self.numberOfViolations?.stringValue = "0 Violations"
        self.logStartDate?.stringValue = ""
        self.numberOfViolations?.textColor = NSColor.init(white: 40/255.0, alpha: 1.0)
        let startDate = (self.startDate?.dateValue)!
        let endDate = (self.endDate?.dateValue)!
        let awsKey = (self.awsKey?.stringValue)!
        let awsSecret = (self.awsSecret?.stringValue)!
        let awsRegion = (self.awsRegion?.selectedItem!.identifier?.rawValue)!
        
        keychain[kAWSSecret] = awsSecret
        keychain[kAWSKey] = awsKey
        keychain[kAWSRegion] = awsRegion
        
        engine = OpenWatchEngine(awsAccessKey: awsKey, awsSecretKey: awsSecret, awsRegion: awsRegion)
        engine.getParametersState = (getParametersCheckbox?.state)!
        engine.safeBringupState = (safeBringupCheckbox?.state)!
        engine.roleState = (roleCheckbox?.state)!
        engine.sshState = (sshCheckbox?.state)!
        engine.flowLogState = (flowLogsCheckbox?.state)!
        engine.runCommandState = (runCommandCheckbox?.state)!
        engine.deleteLogsState = (deleteLogsCheckbox?.state)!
        self.violationTable?.reloadData()
        self.sourceCodeTable?.reloadData()
        
        DispatchQueue.main.async() {
            self.resultText?.textColor = NSColor.init(red: 150.0/255, green: 150.0/255, blue: 150.0/255, alpha: 1.0)
            self.resultText?.stringValue = "Beginning audit ..."
        }
        
        self.engine.beginAudit(
            from: startDate,
            until: endDate,
            sourceFolderPath: localFolderPath,
            progressUpdateCallback: {
                if self.updateUIQueue.operationCount == 0 {
                    self.updateUIQueue.addOperation {
                        usleep(200000)
                        DispatchQueue.main.async { self.updateUI() }
                    }
                }
            },
            auditFinished: {
                DispatchQueue.main.async { self.updateUI(); }
                self.unfreezeUI()
            }
        )
    }
    
    func updateUI() {
        let progress = self.engine.estimatedPercentageComplete()
        self.percentComplete?.stringValue = String(progress) + "%"
        self.percentComplete?.stringValue = "\((progress).rounded(toPlaces: 1))%"
        self.progressBar?.doubleValue = Double(progress)
        DockProgress.progressValue = progress / 100.0
        
        if self.engine.furthestStartLog > 0 {
            let daysAgo = self.engine.furthestStartLog / 86400
            let startDate = Date.init(timeIntervalSinceNow: TimeInterval(self.engine.furthestStartLog * -1))
            let awsDateFormat = DateFormatter()
            awsDateFormat.dateFormat = "yyyy-MM-dd HH:mm"
            let stringGivenDate = awsDateFormat.string(from: startDate)
    
            if daysAgo >= 30 {
                self.logStartDate?.stringValue = "Latest Log Start Date: \(stringGivenDate) (more than \(daysAgo) days ago: make sure logs are up to date)"
            }
            else {
                self.logStartDate?.stringValue = "Latest Log Start Date: \(stringGivenDate)"
            }
        }
        else {
            self.logStartDate?.stringValue = ""
        }
        
        if engine.violations.count > 0 {
            if engine.violations.count > 1 {
                self.numberOfViolations?.stringValue = "\(engine.violations.count) Violations"
            }
            else {
                self.numberOfViolations?.stringValue = "\(engine.violations.count) Violation"
            }
            
            self.numberOfViolations?.textColor = NSColor.init(red: 100.0/255, green: 20.0/255, blue: 20.0/255, alpha: 1.0)
        }
        
        if let failureReason = engine.failureToAuditReason {
            self.resultText?.textColor = NSColor.init(red: 100.0/255, green: 20.0/255, blue: 20.0/255, alpha: 1.0)
            self.resultText?.stringValue = "Audit stopped: \(failureReason)"
            self.percentComplete?.stringValue = String(0) + "%"
            self.progressBar?.doubleValue = Double(0)
            return
        }
        
        if let currentTask = engine.auditTask.currentTask(), let totalParts = engine.auditTask.tasks?.count {
            let currentTaskNumber = engine.auditTask.currentTaskNumber()
            self.resultText?.stringValue = "Part \(currentTaskNumber) of \(totalParts): \(currentTask.taskName): \(currentTask.completedSubtasks) of \(currentTask.numberOfSubtasks)"
            
        }
        self.resultText?.textColor = NSColor.init(red: 150.0/255, green: 150.0/255, blue: 150.0/255, alpha: 1.0)
        
        if (engine.auditTask.tasks?.last?.isFinished())! {
            self.percentComplete?.stringValue = String("100%")
            self.progressBar?.doubleValue = Double(100.0)
            DockProgress.progressValue = 100.0 / 100.0
            
            self.resultText?.stringValue = "Audit completed. Processed \(engine.processDigestsTask.numberOfSubtasks) digests & \(engine.processLogsTask.numberOfSubtasks) logfiles."
            
            if engine.violations.count == 0 {
                self.numberOfViolations?.textColor = NSColor.init(red: 20.0/255, green: 160.0/255, blue: 20.0/255, alpha: 1.0)
            }
            
        }
        
        self.violationTable?.reloadData()
        self.sourceCodeTable?.reloadData()
    }
    
    
    func freezeUI() {
        DispatchQueue.main.async() {
            self.flowLogsCheckbox?.isEnabled = false
            self.runCommandCheckbox?.isEnabled = false
            self.getParametersCheckbox?.isEnabled = false
            self.safeBringupCheckbox?.isEnabled = false
            self.roleCheckbox?.isEnabled = false
            self.sshCheckbox?.isEnabled = false
            self.deleteLogsCheckbox?.isEnabled = false
            self.analyzeButton?.isEnabled = false
            self.startDate?.isEnabled = false
            self.endDate?.isEnabled = false
            self.awsKey?.isEnabled = false
            self.awsSecret?.isEnabled = false
            self.awsRegion?.isEnabled = false
            self.chooseFolderButton?.isEnabled = false
        }
    }
    
    func unfreezeUI() {
        DispatchQueue.main.async() {
            self.runCommandCheckbox?.isEnabled = true
            self.flowLogsCheckbox?.isEnabled = true
            self.getParametersCheckbox?.isEnabled = true
            self.safeBringupCheckbox?.isEnabled = true
            self.roleCheckbox?.isEnabled = true
            self.sshCheckbox?.isEnabled = true
            self.deleteLogsCheckbox?.isEnabled = true
            self.analyzeButton?.isEnabled = true
            self.startDate?.isEnabled = true
            self.endDate?.isEnabled = false //eventually allow end date selection
            self.awsKey?.isEnabled = true
            self.awsSecret?.isEnabled = true
            self.awsRegion?.isEnabled = true
            self.chooseFolderButton?.isEnabled = true
        }
    }
    
    @IBAction func pickLocalSource(sender : NSButton) {
        let dialog = NSOpenPanel();
        
        dialog.title                   = "Choose a CloudTrail folder";
        dialog.showsResizeIndicator    = true;
        dialog.showsHiddenFiles        = false;
        dialog.canChooseDirectories    = true;
        dialog.canCreateDirectories    = false;
        dialog.allowsMultipleSelection = false;
        
        if (dialog.runModal() == NSApplication.ModalResponse.OK) {
            let result = dialog.url // Pathname of the file
            
            if (result != nil) {
                let path = result!.path
                localFolderPath = path
                sourceURL?.stringValue = "\(path)"
            }
        } else {
            // User clicked on "Cancel"
            return
        }
    }
    
    @IBAction func closeApp(sender : NSButton) {
        NSApp.terminate(self)
    }
    
    //MARK: - RULE VIOLATION TABLE
    
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        
        if tableView == violationTable {
            if let cell = tableView.makeView(withIdentifier: NSUserInterfaceItemIdentifier(rawValue: "violationName"), owner: nil) as? NSTableCellView {
                
                let vio = engine.violations[row]
                if (tableColumn?.identifier)!.rawValue == "violationName" {
                    cell.textField?.stringValue = vio.name ?? "-"
                }
                else if (tableColumn?.identifier)!.rawValue == "time" {
                    if let time = vio.eventTime {
                        let awsDateFormat = DateFormatter()
                        awsDateFormat.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
                        let stringGivenDate = awsDateFormat.date(from: time)
                        let humanReadableFormat = DateFormatter()
                        humanReadableFormat.dateStyle = DateFormatter.Style.medium
                        let humanReadableDate = humanReadableFormat.string(from: stringGivenDate!)
                        
                        cell.textField?.stringValue = humanReadableDate
                    }
                    else {
                        cell.textField?.stringValue = "-"
                    }
                }
                else if (tableColumn?.identifier)!.rawValue == "region" {
                    cell.textField?.stringValue = vio.awsRegion ?? "-"
                }
                else if (tableColumn?.identifier)!.rawValue == "ip" {
                    cell.textField?.stringValue = vio.sourceIP ?? "-"
                }
                else if (tableColumn?.identifier)!.rawValue == "filePath" {
                    cell.textField?.stringValue = vio.filePath ?? "-"
                }
                return cell
            }
            return nil
        }
        else {
            if let cell = tableView.makeView(withIdentifier: NSUserInterfaceItemIdentifier(rawValue: "deployCell"), owner: nil) as? NSTableCellView {
                
                var allKeys = Array<String>(engine.sourceRepos.keys)
                if allKeys.count > row {
                    var title = cell.textField
                    var url = cell.viewWithTag(1) as? HyperlinkTextField
                    title?.stringValue = allKeys[row]
                    
                    //modify URL to allow for S3 download for authenticated users
                    if let rawURL = engine.sourceRepos[allKeys[row]] as? String {
                        let downloadableURL = rawURL.replacingOccurrences(of: "s3.amazonaws.com/", with: "s3.console.aws.amazon.com/s3/object/")
                        url?.stringValue = downloadableURL
                        url?.href = downloadableURL
                    }
                }
                else {
                    var title = cell.textField
                    title?.stringValue = ""
                    var url = cell.viewWithTag(1) as! NSTextField
                    url.stringValue = ""
                }
                
                return cell
            }
            
            return nil
        }
    }
    
    func numberOfRows(in tableView: NSTableView) -> Int {
        if engine == nil {
            return 0
        }
        if tableView == violationTable {
            if engine == nil {
                return 0
            }
            return engine.violations.count
        }
        else {
            return Array(engine.sourceRepos.keys).count
        }
    }
    

    //MARK: - VARIABLES
    
    var engine : OpenWatchEngine!
    var updateUIQueue = OperationQueue.init()
    var localFolderPath : String? = nil
    
    @IBOutlet var awsKey : NSTextField?
    @IBOutlet var awsSecret : NSTextField?
    @IBOutlet var awsRegion : NSPopUpButton?
    
    @IBOutlet var sourceTab : NSTabView?
    @IBOutlet var startDate : NSDatePicker?
    @IBOutlet var endDate : NSDatePicker?
    @IBOutlet var sourceURL : NSTextField?
    @IBOutlet var chooseFolderButton : NSButton?
    
    @IBOutlet var sourceCodeTable : NSTableView?
    @IBOutlet var violationTable : NSTableView?
    @IBOutlet var progressBar : NSProgressIndicator?
    @IBOutlet var percentComplete : NSTextField?
    @IBOutlet var resultText : NSTextField?
    @IBOutlet var numberOfViolations : NSTextField?
    @IBOutlet var logStartDate : NSTextField?
    
    
    @IBOutlet var analyzeButton : NSButton?
    @IBOutlet var getParametersCheckbox : NSButton?
    @IBOutlet var safeBringupCheckbox : NSButton?
    @IBOutlet var roleCheckbox : NSButton?
    @IBOutlet var sshCheckbox : NSButton?
    @IBOutlet var flowLogsCheckbox : NSButton?
    @IBOutlet var runCommandCheckbox : NSButton?
    @IBOutlet var deleteLogsCheckbox : NSButton?
    
}

