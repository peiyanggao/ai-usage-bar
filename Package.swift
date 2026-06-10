// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AIUsageBar",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        .executableTarget(
            name: "AIUsageBar",
            path: "Sources/AIUsageBar",
            swiftSettings: [
                .swiftLanguageMode(.v5)
            ]
        )
    ]
)
