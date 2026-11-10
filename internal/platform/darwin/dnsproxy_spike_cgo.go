//go:build darwin && cgo

package darwin

/*
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

static int spikePump(volatile BOOL *done, double seconds) {
	NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:seconds];
	while (!*done && [[NSDate date] compare:deadline] == NSOrderedAscending) {
		CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, false);
	}
	return *done ? 1 : 0;
}

static void spikeSetErr(char **errOut, NSString *msg) {
	if (errOut) *errOut = strdup([msg UTF8String]);
}

// SPIKE (SECENG-308): saves or removes an NEDNSProxyManager configuration
// for the extension's DNSProxyProvider. Do not merge.
static int dnsSpikeSet(int on, const char *bundleID, char **errOut) {
	@autoreleasepool {
		NEDNSProxyManager *mgr = [NEDNSProxyManager sharedManager];
		__block volatile BOOL done = NO;
		__block NSError *err = nil;
		[mgr loadFromPreferencesWithCompletionHandler:^(NSError *e) { err = e; done = YES; }];
		if (!spikePump(&done, 15.0) || err != nil) {
			spikeSetErr(errOut, err ? [err localizedDescription] : @"loading the DNS proxy configuration timed out");
			return -1;
		}
		done = NO;
		if (on) {
			NEDNSProxyProviderProtocol *proto = [[NEDNSProxyProviderProtocol alloc] init];
			proto.providerBundleIdentifier = [NSString stringWithUTF8String:bundleID];
			proto.serverAddress = @"127.0.0.1";
			mgr.providerProtocol = proto;
			mgr.localizedDescription = @"AgentMon DNS spike";
			mgr.enabled = YES;
			[mgr saveToPreferencesWithCompletionHandler:^(NSError *e) { err = e; done = YES; }];
		} else {
			[mgr removeFromPreferencesWithCompletionHandler:^(NSError *e) { err = e; done = YES; }];
		}
		if (!spikePump(&done, 120.0)) {
			spikeSetErr(errOut, @"saving the DNS proxy configuration timed out; the approval prompt may still be open");
			return 1;
		}
		if (err != nil) {
			spikeSetErr(errOut, [err localizedDescription]);
			return -1;
		}
		return 0;
	}
}
*/
import "C"

import "unsafe"

// SetDNSSpike saves (on) or removes (off) the spike DNS proxy configuration.
func SetDNSSpike(on bool) (ActivateResult, error) {
	cID := C.CString(sysExtBundleID)
	defer C.free(unsafe.Pointer(cID))
	var cErr *C.char
	flag := C.int(0)
	if on {
		flag = 1
	}
	result := C.dnsSpikeSet(flag, cID, &cErr)
	return ActivateResult(result), takeProxyErr(cErr)
}
