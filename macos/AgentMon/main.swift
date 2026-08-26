// macos/SysExt/main.swift
import Foundation
import NetworkExtension
import SystemExtensions

// 1. Initialize policy cache BEFORE ES client (avoid lazy init on ES thread)
_ = SessionPolicyCache.shared

// 2. Create ES client (calls es_new_client but does NOT subscribe yet)
var esfClient: ESFClient?
for attempt in 1...3 {
    if let client = ESFClient.create() {
        NSLog("AgentMon SysExt: ES client created on attempt \(attempt)")
        esfClient = client
        break
    }
    if attempt < 3 {
        NSLog("AgentMon SysExt: ES client creation attempt \(attempt) failed, retrying in 2s")
        Thread.sleep(forTimeInterval: 2)
    }
}

guard let esfClient = esfClient else {
    NSLog("AgentMon SysExt: ES client failed to start -- exiting (grant Full Disk Access to enable)")
    exit(1)
}

// 3. Store strong reference BEFORE subscribing
ESFClient.shared = esfClient

// 4. Subscribe to events -- ESFClient.shared is now set, safe for NOTIFY handlers
guard esfClient.subscribe() else {
    NSLog("AgentMon SysExt: Failed to subscribe to ES events -- exiting")
    exit(1)
}

// 5. Start async socket connection (lazy, non-blocking)
PolicySocketClient.shared.connectWhenReady()

// 6. Enter NetworkExtension mode so the providers declared in Info.plist under
// NEProviderClasses can be instantiated by the system.
//
// This registers the provider classes and returns; it does not start any
// filtering. FilterDataProvider.startFilter runs only once a NEFilterManager
// configuration exists and is enabled, which nothing installs yet. Until then
// this call is inert -- but without it the providers can never be created at
// all, which is why network and DNS rules have been silently unenforced.
//
// Ordering matters. It runs after the ES client is subscribed so that a
// failure here cannot cost us file and exec enforcement, which is the only
// macOS enforcement that currently works. It runs before dispatchMain()
// because startSystemExtensionMode must be called before the run loop starts.
if #available(macOS 10.15, *) {
    NSLog("AgentMon SysExt: entering NetworkExtension mode")
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
