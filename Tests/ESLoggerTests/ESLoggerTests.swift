import XCTest
@testable import ESLogger

final class ESLoggerTests: XCTestCase {
    var eslogger: ESLoggerFile? = nil
    var storedEvents = [ESMessage]()
    var storedErrors = [ESLogger.Error]()

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {

    }

    func callbackEvent(_ message: ESMessage) {
        storedEvents.append(message)
    }

    func callbackError(_ error: ESLogger.Error) {
        print(storedEvents.count)
        storedErrors.append(error)
    }

    func doClear() {
        storedEvents.removeAll()
        storedErrors.removeAll()
    }

    func runESLogger(withFileURL: URL) {
        eslogger = ESLoggerFile(withFileURL: withFileURL, callHandler: callbackEvent, errorHandler: callbackError)
        eslogger?.start()
    }

    func testV6EventParsing() throws {
        doClear()
        runESLogger(withFileURL: URL(fileURLWithPath: "Tests/JSON/esloggerEvents.unique.json"))

        XCTAssertEqual(storedEvents.count, 61, "Expecting to load exactly 61 events from test file")
        var last = 0
        for event in storedEvents {
            if last+1 != event.global_seq_num {
                print("missing events between \(last) and \(event.global_seq_num)")
            }
            last = event.global_seq_num
        }
    }

    func testInvalidJSONValue() throws {
        doClear()
        runESLogger(withFileURL: URL(fileURLWithPath: "Tests/JSON/esloggerEvents_test_invalidJSONvalue.json"))

        XCTAssertEqual(storedEvents.count, 1, "Expecting to load one of two events")
        XCTAssertEqual(storedErrors.count, 1, "Expecting exactly one error message about asid value")
        XCTAssertEqual(eslogger?.eventsDropped, 1, "Expected to see one registered event dropped")
    }

    func testInvalidJSONMissingKey() throws {
        doClear()
        runESLogger(withFileURL: URL(fileURLWithPath: "Tests/JSON/esloggerEvents_test_missingJSONkey.json"))

        XCTAssertEqual(storedEvents.count, 0, "Expecting to load none of two events")
        XCTAssertEqual(storedErrors.count, 2, "Expecting exactly one error message about  value")
        XCTAssertEqual(eslogger?.eventsDropped, 2, "Expected to see one registered event dropped")
    }

    func testInvalidJSONMissingCurly() throws {
        doClear()
        runESLogger(withFileURL: URL(fileURLWithPath: "Tests/JSON/esloggerEvents_test_missing_curly.json"))

        XCTAssertEqual(storedEvents.count, 2, "Expecting to load two of three events")
        // doesn't report error for this situation by design
        XCTAssertEqual(eslogger?.eventsDropped, 1, "Expected to see one registered event dropped")
    }

    func testEmptyFile() throws {
        doClear()
        runESLogger(withFileURL: URL(fileURLWithPath: "Tests/JSON/esloggerEvents_test_emptyfile.json"))

        XCTAssertEqual(storedErrors.count, 1, "Expecting exactly one error message about invalid file data")
    }
}
