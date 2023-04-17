//
//  ESLogger.swift
//  ESLogger
//
//  Created by nub on 2/1/23.
//  Copyright (c) 2023 nubco, llc
//

import Foundation
import Subprocess
import Logging

//
//  Read from running eslogger (requires root privs)
//
public class ESLogger {
    public enum Error: Swift.Error {
        case noValidRequestedEvents
        case cannotListESLoggerEvents

        case needRootPermission
        case needTCCFullDiskAccess
        case tooManyConnections
        case invalidArgument
        case needEntitlement

        case invalidDataInFile
        case errorReadingFromFile(message: String)

        case jsonMissingKey(keyName: String)
        case jsonInvalidValue(valueName: String)
        case jsonDecodeError(message: String)

        case internalError(message: String)
    }

    static let esloggerLocation = "/usr/bin/eslogger"
    fileprivate var log = Logger(label: "xyz.nubco.ESLogger.ESLogger")
    fileprivate var process: Subprocess?
    fileprivate let callback: (ESMessage) -> Void
    fileprivate let errCallback: (Error) -> Void
    public private(set) var lastGlobalSeqNum = -1
    private var previousEventJSONDecodeError = ""

    public private(set) var requestedEventNames: [String] = []
    public fileprivate(set) var eventsDropped = 0
    public fileprivate(set) var eventsSeen = 0

    public var isRunning: Bool { process?.isRunning ?? false }

    public var printJSON: Bool = false
    public var onlyJSON: Bool = true

    // for subclass
    init(callHandler callback: @escaping (ESMessage) -> Void,
         errorHandler errCallback: @escaping (Error) -> Void,
         withLogLevel: Logger.Level = .info) {
        self.callback = callback
        self.errCallback = errCallback
        log.logLevel = withLogLevel
    }

    public init(forEvents eventNames: Set<String>,
                callHandler callback: @escaping (ESMessage) -> Void,
                errorHandler errCallback: @escaping (Error) -> Void,
                withLogLevel: Logger.Level = .info,
                qos: DispatchQoS = .default) throws {
        self.callback = callback
        self.errCallback = errCallback
        log.logLevel = withLogLevel

        guard let validEventNames = ValidESLoggerEvents(withLogLevel: withLogLevel).validEvents else {
            throw Error.cannotListESLoggerEvents
        }

        // make sure eventNames are valid before passing
        requestedEventNames.append(contentsOf: validEventNames.intersection(eventNames))
        if requestedEventNames.isEmpty {
            log.debug("no valid requested events")
            throw Error.noValidRequestedEvents
        }

        let esloggerCommand = [ESLogger.esloggerLocation] + requestedEventNames
        log.debug("ESLogger command", metadata: ["command": "\(esloggerCommand)"])
        process = Subprocess(esloggerCommand, qos: qos)
    }

    public func start() throws {
        if isRunning {
            log.debug("already running, returning without side-effect")
            return
        }

        log.debug("Executing ESLogger")
        try process!.launch(outputHandler: self.processEvent,
                            errorHandler: { data in
                                let input = String(decoding: data, as: UTF8.self)
                                self.log.debug("ESLogger stderr", metadata: ["error": "\(input)"])

                                var theError: Error
                                if input.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED") {
                                    theError = Error.needTCCFullDiskAccess
                                } else if input.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED") {
                                    theError = Error.needRootPermission
                                } else if input.contains("ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS") {
                                    theError = Error.tooManyConnections
                                } else if input.contains("ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT") {
                                    theError = Error.invalidArgument
                                } else if input.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED") {
                                    theError = Error.needEntitlement
                                } else {
                                    theError = Error.internalError(message: input)
                                }

                                self.errCallback(theError)
                            },
                            terminationHandler: { _ in
                                self.log.debug("ESLogger exiting")
                            }
        )
    }

    public func stop() {
        log.trace("stopping ESLogger")
        if !isRunning {
            return
        }

        process?.kill()
        process?.waitForTermination()
    }

    func processEvent(_ data: Data) {
        let input = String(decoding: data, as: UTF8.self)
        processEvent(fromString: input)
    }

    func processEvent(fromString input: String) {
        log.trace("ESLogger input", metadata: ["data": "\(input)"])
        for var event in input.components(separatedBy: .newlines) {
            if event.isEmpty { log.trace("Skipping empty string"); continue }
            eventsSeen += 1

            // previous decode error *might* mean that we didn't get a full line
            // so lets combine the last failed attempt with this new one
            if !previousEventJSONDecodeError.isEmpty {
                if event.first != "{" {
                    log.debug("Combining events due to previous decode error - appending",
                              metadata: ["newstring": "\(event)"])
                    event = previousEventJSONDecodeError + event
                } else {
                    // callback might overwhelm owner ex: 100K events all decode errors
                    // errCallback(Error.jsonDecodeError(message: <#T##String#>))
                    eventsDropped += 1
                }
                previousEventJSONDecodeError = ""
            }

            if printJSON {
                log.info("Event received", metadata: ["EventAsString": "\(event)"])
                if onlyJSON {
                    continue
                }
            } else {
                log.debug("Event from ESLogger", metadata: ["string": "\(event)"])
            }

            do {
                if let eventData = event.data(using: .utf8) {
                    let jsonEvent = try JSONDecoder().decode(ESMessage.self, from: eventData)
                    log.trace("Decoded JSON", metadata: ["event": "\(jsonEvent)"])

                    if lastGlobalSeqNum != -1 && jsonEvent.global_seq_num > lastGlobalSeqNum+1 {
                        log.debug("""
                        kernel dropped events for us - event: \(jsonEvent.global_seq_num) \
                        last: \(self.lastGlobalSeqNum)
                        """)
                        eventsDropped += (jsonEvent.global_seq_num-1) - lastGlobalSeqNum
                    }
                    lastGlobalSeqNum = jsonEvent.global_seq_num
                    callback(jsonEvent)
                }
            } catch Swift.DecodingError.keyNotFound(let codingKey, _) {
                log.debug("Dropping event, JSON missing key", metadata: ["key": "\(codingKey.stringValue)"])
                errCallback(Error.jsonMissingKey(keyName: codingKey.stringValue))
                previousEventJSONDecodeError = ""
                eventsDropped += 1
            } catch Swift.DecodingError.typeMismatch(let expectedType, let context) {
                log.debug("Dropping event, JSON invalid value type",
                          metadata: ["expectedType": "\(expectedType)", "context": "\(context)"])
                errCallback(Error.jsonInvalidValue(valueName: context.codingPath.last?.stringValue ?? ""))
                previousEventJSONDecodeError = ""
                eventsDropped += 1
            } catch Swift.DecodingError.valueNotFound(let expected, let context) {
                log.debug("Dropping event, JSON invalid value",
                          metadata: ["expectedType": "\(expected)", "context": "\(context)"])
                errCallback(Error.jsonInvalidValue(valueName: context.codingPath.last?.stringValue ?? ""))
                previousEventJSONDecodeError = ""
                eventsDropped += 1
            } catch {
                log.debug("JSON decode error", metadata: ["error": "\(error)"])
                // error gets thrown when checking if next input processed starts with "{"
                // this is how we handle events that get split across more than one line.
                previousEventJSONDecodeError = event
            }
        }
    }
}

//
//  Read from file on disk
//
public class ESLoggerFile: ESLogger {
    private let fileURL: URL
    private var active = false
    override public var isRunning: Bool { return active }

    public init(withFileURL fileURL: URL,
                callHandler callback: @escaping (ESMessage) -> Void,
                errorHandler errCallback: @escaping (Error) -> Void,
                withLogLevel: Logger.Level = .info) {
        self.fileURL = fileURL
        super.init(callHandler: callback, errorHandler: errCallback, withLogLevel: withLogLevel)
    }

    public static func validFileHeader(inFileURL: URL) -> Bool {
        // guard let expectedHeader = "{\"schema_version\":1,\"mach_time\":".data(using: .utf8) else { return false }
        guard let expectedHeader = "{".data(using: .utf8) else { return false }
        guard let fileHandle = FileHandle(forReadingAtPath: inFileURL.path) else { return false }
        defer {
            if #available(macOS 10.15, *) {
                try? fileHandle.close()
            } else {
                fileHandle.closeFile()
            }
        }

        let fileHeader = fileHandle.readData(ofLength: expectedHeader.count)
        return fileHeader == expectedHeader
    }

    override public func start() {
        active = true
        defer {
            active = false
        }

        if !ESLoggerFile.validFileHeader(inFileURL: fileURL) {
            errCallback(Error.invalidDataInFile)
            return
        }

        // read the file by mapping to stdin
        guard let file = freopen(fileURL.path, "r", stdin) else { return }
        defer {
            fclose(file)
        }

        while let line = readLine(), active {
            self.processEvent(fromString: line)
        }
    }

    override public func stop() {
        active = false
    }
}

//
//  Read from file on disk continuously
//
public class ESLoggerTail: ESLogger {
    static let tailLocation = "/usr/bin/tail"

    public init(withFileURL fileURL: URL,
                callHandler callback: @escaping (ESMessage) -> Void,
                errorHandler errCallback: @escaping (Error) -> Void,
                withLogLevel: Logger.Level = .info,
                qos: DispatchQoS = .default,
                followFile: Bool = false) {
        super.init(callHandler: callback, errorHandler: errCallback, withLogLevel: withLogLevel)

        // -F creates so many open events default to -f
        let optionF = followFile ? "-F" : "-f"
        let tailCommand = [ESLoggerTail.tailLocation, "-n", "+0", optionF, fileURL.path]
        log.debug("Tail command", metadata: ["command": "\(tailCommand)"])
        process = Subprocess(tailCommand, qos: qos)
    }

    override public func start() throws {
        if isRunning {
            log.debug("already running, returning without side-effect")
            return
        }

        log.debug("Executing tail")
        try process!.launch(outputHandler: self.processEvent,
                            errorHandler: { data in
                                let input = String(decoding: data, as: UTF8.self)
                                self.log.debug("tail stderr", metadata: ["error": "\(input)"])
                                var theError: Error
                                if input.contains("Permission") {
                                    theError = Error.errorReadingFromFile(message: "Permission Denied")
                                } else if input.contains("Is a directory") {
                                    theError = Error.errorReadingFromFile(message: "reading from directory not a file")
                                } else {
                                    theError = Error.internalError(message: input)
                                }
                                self.errCallback(theError)
                            },
                            terminationHandler: { _ in
                                self.log.debug("tail exiting")
                            }
        )
    }
}

public class ValidESLoggerEvents {
    private var log = Logger(label: "xyz.nubco.ESLogger.ValidESLoggerEvents")
    private var events: Set<String> = Set([])
    public var validEvents: Set<String>? {
        get {
            if !events.isEmpty {
                return events
            }

            return self.gatherValidEventNames()
        }

        set {
            events = Set([])
        }
    }

    public init(withLogLevel: Logger.Level = .info) {
        log.logLevel = withLogLevel
    }

    private func gatherValidEventNames() -> Set<String>? {
        let findEventsCommand = [ESLogger.esloggerLocation, "--list-events"]

        var eventNames: Set<String>
        do {
            log.debug("Locating valid events", metadata: ["command": "\(findEventsCommand)"])
            let output = String(decoding: try Shell(findEventsCommand).exec(), as: UTF8.self)
            log.trace("Output from eslogger", metadata: ["output": "\(output)"])
            eventNames = Set(output.components(separatedBy: .newlines))
        } catch {
            log.debug("Locating valid events", metadata: ["error": "\(error)"])
            return nil
        }

        // spot check what we got back is semi-sane
        if !eventNames.contains("readdir") ||
           !eventNames.contains("exec") ||
           !eventNames.contains("setgid") {
            log.debug("Invalid reponse from ESLogger", metadata: ["ProposedEventNames": "\(eventNames)"])
            return nil
        }

        events = eventNames
        return eventNames
    }
}
