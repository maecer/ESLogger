# ESLogger

A Swift library for parsing `eslogger` JSON output into Swift objects.

Developed using XCode 14.2 and Swift 5.7

## Usage

#### Reading from file

```swift
let eslogger = ESLoggerFile(withFileURL: theFileURL,
                            callHandler: { event in dump(event) }, 
                            errorHandler: { error in print("\(error)") })
eslogger.start()
```

#### Reading from tail

```swift
let eslogger = ESLoggerTail(withFileURL: theFileURL,
                            callHandler: { event in dump(event) },
                            errorHandler: { error in print("\(error)") })
try eslogger.start()
```


#### Running eslogger directly
This requires running code as root.  An `eslogger` requirement.

```swift
let eventTypes = ["exec", "fork", "exit", ]
let eslogger = try ESLogger(forEvents: eventTypes, 
                            callHandler: { event in dump(event) },
                            errorHandler: { error in print("\(error)") })
try eslogger.start()
```




## Installation

### Swift Package Manager (OS X)
You can use the [Swift Package Manager](https://swift.org/package-manager) to install ESLogger by adding the proper descriptions to your `Package.swift` file:
```swift
import PackageDescription

let package = Package(
	name: "{YOUR_PROJECT}",
	dependencies: [
		.package(url: "https://github.com/nubcoxyz/ESLogger.git", from: "1.0.0"),
	]
)
```

## Credits

- Subprocess - Copyright (c) 2020 Jamf Open Source Community - [LICENSE](https://github.com/jamf/Subprocess/blob/master/LICENSE)
- swift-log - Copyright (c) 2018, 2019 The SwiftLog Project - [LICENSE](https://github.com/apple/swift-log/blob/main/LICENSE.txt)

## License

ESLogger is released under the [MIT License](https://github.com/nubcoxyz/ESLogger/blob/master/LICENSE) - Copyright (c) 2023 nubco

