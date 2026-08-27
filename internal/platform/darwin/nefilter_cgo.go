//go:build darwin && cgo

package darwin

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework NetworkExtension -framework Foundation

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

enum {
	FILTER_OK = 0,
	FILTER_NEEDS_APPROVAL = 1,
	FILTER_FAILED = -1,
};

// pumpUntilDone runs the calling thread's run loop until *done is set or the
// deadline passes. NEFilterManager delivers its completion handlers on the main
// queue, so a plain dispatch_semaphore_wait here would deadlock whenever this is
// called from the main thread -- which is exactly where a cobra RunE body runs.
// Pumping the run loop drains that queue and also picks up a handler delivered
// on any other thread on the next poll. Returns 1 if the work completed.
static int pumpUntilDone(volatile BOOL *done, double seconds) {
	NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
	while (!*done && [[NSDate date] compare:deadline] == NSOrderedAscending) {
		CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, false);
	}
	return *done ? 1 : 0;
}

// loadFilterPrefs pulls the current NEFilterManager configuration into the
// shared manager. Every mutation must be preceded by a load: saving onto a
// manager that was never loaded fails with a stale-configuration error, and the
// failure is easy to misread as a permissions problem.
static int loadFilterPrefs(NEFilterManager *mgr, char **errOut) {
	__block volatile BOOL done = NO;
	__block NSError *loadErr = nil;
	[mgr loadFromPreferencesWithCompletionHandler:^(NSError *e) {
		loadErr = e;
		done = YES;
	}];
	if (!pumpUntilDone(&done, 15.0)) {
		if (errOut) *errOut = strdup("loading the content filter configuration timed out after 15 seconds");
		return FILTER_FAILED;
	}
	if (loadErr != nil) {
		if (errOut) *errOut = strdup([[loadErr localizedDescription] UTF8String]);
		return FILTER_FAILED;
	}
	return FILTER_OK;
}

// installContentFilter creates or updates the content filter configuration and
// enables it. Enabling is what actually starts the extension's
// FilterDataProvider: NEProvider.startSystemExtensionMode only registers the
// provider class, and startFilter is never called until a configuration exists
// and is enabled. Without this, every network rule on macOS is inert.
//
// The first save shows the user a "would like to filter network content" prompt.
// Declining it surfaces as a save error, which is reported rather than swallowed.
static int installContentFilter(const char *desc, const char *org, char **errOut) {
	@autoreleasepool {
		NEFilterManager *mgr = [NEFilterManager sharedManager];

		int rc = loadFilterPrefs(mgr, errOut);
		if (rc != FILTER_OK) return rc;

		NEFilterProviderConfiguration *cfg = mgr.providerConfiguration;
		if (cfg == nil) {
			cfg = [[NEFilterProviderConfiguration alloc] init];
		}
		// filterSockets is the flag that routes flows to handleNewFlow. Packet
		// filtering stays off: the provider makes per-flow decisions, and a
		// packet filter would add a second, redundant data path.
		cfg.filterSockets = YES;
		cfg.filterPackets = NO;
		if (org != NULL) {
			cfg.organization = [NSString stringWithUTF8String:org];
		}
		mgr.providerConfiguration = cfg;
		if (desc != NULL) {
			mgr.localizedDescription = [NSString stringWithUTF8String:desc];
		}
		mgr.enabled = YES;

		__block volatile BOOL done = NO;
		__block NSError *saveErr = nil;
		[mgr saveToPreferencesWithCompletionHandler:^(NSError *e) {
			saveErr = e;
			done = YES;
		}];
		// Generous: the deadline covers the user reading and answering the
		// system prompt on a first install.
		if (!pumpUntilDone(&done, 120.0)) {
			if (errOut) *errOut = strdup("saving the content filter configuration timed out; the approval prompt may still be open");
			return FILTER_NEEDS_APPROVAL;
		}
		if (saveErr != nil) {
			if (errOut) *errOut = strdup([[saveErr localizedDescription] UTF8String]);
			return FILTER_FAILED;
		}
		return FILTER_OK;
	}
}

// removeContentFilter deletes the content filter configuration.
//
// Run this before deactivating the system extension. A configuration left
// behind after the extension is gone keeps an entry in System Settings >
// Network > Filters that refers to nothing, and the next install inherits it.
static int removeContentFilter(char **errOut) {
	@autoreleasepool {
		NEFilterManager *mgr = [NEFilterManager sharedManager];

		int rc = loadFilterPrefs(mgr, errOut);
		if (rc != FILTER_OK) return rc;

		if (mgr.providerConfiguration == nil) {
			// Nothing installed; removal is a no-op rather than an error.
			return FILTER_OK;
		}

		__block volatile BOOL done = NO;
		__block NSError *rmErr = nil;
		[mgr removeFromPreferencesWithCompletionHandler:^(NSError *e) {
			rmErr = e;
			done = YES;
		}];
		if (!pumpUntilDone(&done, 30.0)) {
			if (errOut) *errOut = strdup("removing the content filter configuration timed out after 30 seconds");
			return FILTER_FAILED;
		}
		if (rmErr != nil) {
			if (errOut) *errOut = strdup([[rmErr localizedDescription] UTF8String]);
			return FILTER_FAILED;
		}
		return FILTER_OK;
	}
}

// contentFilterStatus reports whether a configuration exists and whether it is
// enabled. Both are needed: a configuration that exists but is disabled leaves
// startFilter uncalled, which looks identical from the outside to no
// configuration at all.
static int contentFilterStatus(int *installed, int *enabled, char **errOut) {
	@autoreleasepool {
		NEFilterManager *mgr = [NEFilterManager sharedManager];

		int rc = loadFilterPrefs(mgr, errOut);
		if (rc != FILTER_OK) return rc;

		if (installed) *installed = (mgr.providerConfiguration != nil) ? 1 : 0;
		if (enabled) *enabled = mgr.isEnabled ? 1 : 0;
		return FILTER_OK;
	}
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func installContentFilter(description, organization string) (ActivateResult, error) {
	cDesc := C.CString(description)
	defer C.free(unsafe.Pointer(cDesc))
	cOrg := C.CString(organization)
	defer C.free(unsafe.Pointer(cOrg))

	var cErr *C.char
	result := C.installContentFilter(cDesc, cOrg, &cErr)
	if cErr != nil {
		errMsg := C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
		return ActivateResult(result), fmt.Errorf("%s", errMsg)
	}
	return ActivateResult(result), nil
}

func removeContentFilter() (ActivateResult, error) {
	var cErr *C.char
	result := C.removeContentFilter(&cErr)
	if cErr != nil {
		errMsg := C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
		return ActivateResult(result), fmt.Errorf("%s", errMsg)
	}
	return ActivateResult(result), nil
}

func contentFilterStatus() (installed, enabled bool, err error) {
	var cInstalled, cEnabled C.int
	var cErr *C.char
	result := C.contentFilterStatus(&cInstalled, &cEnabled, &cErr)
	if cErr != nil {
		errMsg := C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
		return false, false, fmt.Errorf("%s", errMsg)
	}
	if ActivateResult(result) != ActivateOK {
		return false, false, fmt.Errorf("content filter status probe failed")
	}
	return cInstalled != 0, cEnabled != 0, nil
}
