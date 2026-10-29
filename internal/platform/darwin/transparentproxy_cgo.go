//go:build darwin && cgo

package darwin

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework NetworkExtension -framework Foundation

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

// ARC is required. A completion handler stores its arguments in __block
// variables. Without ARC those are not retained, and the array of managers
// was freed before loadProxyManager read it, which crashed the CLI. cgo
// applies CFLAGS to every file in the package, so the content filter and
// activation code compile with ARC too.

enum {
	PROXY_OK = 0,
	PROXY_NEEDS_APPROVAL = 1,
	PROXY_FAILED = -1,
};

// proxyPump runs the calling thread's run loop until *done is set or the
// deadline passes, for the same reason as pumpUntilDone in nefilter_cgo.go:
// NETransparentProxyManager calls its completion handlers on the main queue.
static int proxyPump(volatile BOOL *done, double seconds) {
	NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
	while (!*done && [[NSDate date] compare:deadline] == NSOrderedAscending) {
		CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, false);
	}
	return *done ? 1 : 0;
}

static void proxySetErr(char **errOut, NSString *msg) {
	if (errOut) *errOut = strdup([msg UTF8String]);
}

// loadProxyManager returns this app's transparent proxy manager, or nil with
// *errOut set. *found reports whether a saved configuration exists.
static NETransparentProxyManager *loadProxyManager(int *found, char **errOut) {
	__block volatile BOOL done = NO;
	__block NSArray<NETransparentProxyManager *> *managers = nil;
	__block NSError *loadErr = nil;
	[NETransparentProxyManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETransparentProxyManager *> *m, NSError *e) {
		managers = m;
		loadErr = e;
		done = YES;
	}];
	if (!proxyPump(&done, 15.0)) {
		proxySetErr(errOut, @"loading the transparent proxy configuration timed out after 15 seconds");
		return nil;
	}
	if (loadErr != nil) {
		proxySetErr(errOut, [loadErr localizedDescription]);
		return nil;
	}
	if (found) *found = managers.count > 0 ? 1 : 0;
	return managers.firstObject ?: [[NETransparentProxyManager alloc] init];
}

static int saveAndReload(NETransparentProxyManager *mgr, double saveSeconds, char **errOut) {
	__block volatile BOOL done = NO;
	__block NSError *saveErr = nil;
	[mgr saveToPreferencesWithCompletionHandler:^(NSError *e) {
		saveErr = e;
		done = YES;
	}];
	if (!proxyPump(&done, saveSeconds)) {
		proxySetErr(errOut, @"saving the transparent proxy configuration timed out; the approval prompt may still be open");
		return PROXY_NEEDS_APPROVAL;
	}
	if (saveErr != nil) {
		proxySetErr(errOut, [saveErr localizedDescription]);
		return PROXY_FAILED;
	}
	// A manager must be loaded again after a save before its connection
	// can start.
	done = NO;
	__block NSError *loadErr = nil;
	[mgr loadFromPreferencesWithCompletionHandler:^(NSError *e) {
		loadErr = e;
		done = YES;
	}];
	if (!proxyPump(&done, 15.0) || loadErr != nil) {
		proxySetErr(errOut, loadErr ? [loadErr localizedDescription] : @"reloading the transparent proxy configuration timed out");
		return PROXY_FAILED;
	}
	return PROXY_OK;
}

// installTransparentProxy saves an enabled configuration for the
// extension's TransparentProxyProvider and starts it. A saved configuration
// does not start the provider by itself.
static int installTransparentProxy(const char *desc, const char *bundleID, char **errOut) {
	@autoreleasepool {
		NETransparentProxyManager *mgr = loadProxyManager(NULL, errOut);
		if (mgr == nil) return PROXY_FAILED;

		NETunnelProviderProtocol *proto = [[NETunnelProviderProtocol alloc] init];
		proto.providerBundleIdentifier = [NSString stringWithUTF8String:bundleID];
		// Required, but unused: the provider sends flows to the daemon over
		// its policy socket.
		proto.serverAddress = @"127.0.0.1";
		mgr.protocolConfiguration = proto;
		mgr.localizedDescription = [NSString stringWithUTF8String:desc];
		mgr.enabled = YES;

		int rc = saveAndReload(mgr, 120.0, errOut);
		if (rc != PROXY_OK) return rc;

		NSError *startErr = nil;
		if (![mgr.connection startVPNTunnelAndReturnError:&startErr]) {
			proxySetErr(errOut, startErr ? [startErr localizedDescription] : @"starting the transparent proxy failed");
			return PROXY_FAILED;
		}
		return PROXY_OK;
	}
}

static int removeTransparentProxy(char **errOut) {
	@autoreleasepool {
		int found = 0;
		NETransparentProxyManager *mgr = loadProxyManager(&found, errOut);
		if (mgr == nil) return PROXY_FAILED;
		if (!found) return PROXY_OK;

		[mgr.connection stopVPNTunnel];
		__block volatile BOOL done = NO;
		__block NSError *rmErr = nil;
		[mgr removeFromPreferencesWithCompletionHandler:^(NSError *e) {
			rmErr = e;
			done = YES;
		}];
		if (!proxyPump(&done, 30.0)) {
			proxySetErr(errOut, @"removing the transparent proxy configuration timed out after 30 seconds");
			return PROXY_FAILED;
		}
		if (rmErr != nil) {
			proxySetErr(errOut, [rmErr localizedDescription]);
			return PROXY_FAILED;
		}
		return PROXY_OK;
	}
}

// transparentProxyStatus reports whether a configuration exists, whether it
// is enabled, and whether its provider is running.
static int transparentProxyStatus(int *installed, int *enabled, int *running, char **errOut) {
	@autoreleasepool {
		int found = 0;
		NETransparentProxyManager *mgr = loadProxyManager(&found, errOut);
		if (mgr == nil) return PROXY_FAILED;
		if (installed) *installed = found;
		if (enabled) *enabled = (found && mgr.isEnabled) ? 1 : 0;
		if (running) *running = (found && mgr.connection.status == NEVPNStatusConnected) ? 1 : 0;
		return PROXY_OK;
	}
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func takeProxyErr(cErr *C.char) error {
	if cErr == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(cErr))
	return fmt.Errorf("%s", C.GoString(cErr))
}

func installTransparentProxy(description string) (ActivateResult, error) {
	cDesc := C.CString(description)
	defer C.free(unsafe.Pointer(cDesc))
	cID := C.CString(sysExtBundleID)
	defer C.free(unsafe.Pointer(cID))
	var cErr *C.char
	result := C.installTransparentProxy(cDesc, cID, &cErr)
	return ActivateResult(result), takeProxyErr(cErr)
}

func removeTransparentProxy() (ActivateResult, error) {
	var cErr *C.char
	result := C.removeTransparentProxy(&cErr)
	return ActivateResult(result), takeProxyErr(cErr)
}

func transparentProxyStatus() (installed, enabled, running bool, err error) {
	var cInstalled, cEnabled, cRunning C.int
	var cErr *C.char
	result := C.transparentProxyStatus(&cInstalled, &cEnabled, &cRunning, &cErr)
	if err := takeProxyErr(cErr); err != nil {
		return false, false, false, err
	}
	if ActivateResult(result) != ActivateOK {
		return false, false, false, fmt.Errorf("transparent proxy status probe failed")
	}
	return cInstalled != 0, cEnabled != 0, cRunning != 0, nil
}
