//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
	yukhKeychainFound = 1,
	yukhKeychainAbsent = 2,
	yukhKeychainUnavailable = 3,
	yukhKeychainInvalid = 4,
	yukhKeychainCreated = 5,
	yukhKeychainAmbiguous = 6
};

static CFStringRef yukhString(const char *value) {
	return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static int yukhOpenExactKeychain(const char *path,
	SecKeychainRef *keychain, CFArrayRef *searchList) {
	struct stat info;
	if (path == NULL || path[0] != '/' || lstat(path, &info) != 0 ||
		!S_ISREG(info.st_mode) || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
		info.st_uid != geteuid()) {
		return 0;
	}
	if (SecKeychainOpen(path, keychain) != errSecSuccess || *keychain == NULL) {
		if (*keychain != NULL) CFRelease(*keychain);
		*keychain = NULL;
		return 0;
	}
	const void *values[] = {*keychain};
	*searchList = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
	if (*searchList == NULL) {
		CFRelease(*keychain);
		*keychain = NULL;
		return 0;
	}
	return 1;
}

static void yukhReleaseKeychainScope(SecKeychainRef keychain, CFArrayRef searchList) {
	if (searchList != NULL) CFRelease(searchList);
	if (keychain != NULL) CFRelease(keychain);
}

static void yukhAddExactQuery(CFMutableDictionaryRef query, CFStringRef service,
	CFStringRef account, CFStringRef accessGroup, CFArrayRef searchList) {
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service);
	CFDictionarySetValue(query, kSecAttrAccount, account);
	if (accessGroup != NULL) {
		CFDictionarySetValue(query, kSecAttrAccessGroup, accessGroup);
	}
	CFDictionarySetValue(query, kSecMatchSearchList, searchList);
	CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
}

static void yukhAddExactCreate(CFMutableDictionaryRef query, CFStringRef service,
	CFStringRef account, CFStringRef accessGroup, SecKeychainRef keychain) {
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service);
	CFDictionarySetValue(query, kSecAttrAccount, account);
	if (accessGroup != NULL) {
		CFDictionarySetValue(query, kSecAttrAccessGroup, accessGroup);
	}
	CFDictionarySetValue(query, kSecUseKeychain, keychain);
	CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
}

static int yukhKeychainLookup(const char *keychainPath, const char *serviceValue, const char *accountValue,
	const char *accessGroupValue, unsigned char output[32]) {
	CFStringRef service = yukhString(serviceValue);
	CFStringRef account = yukhString(accountValue);
	CFStringRef accessGroup = accessGroupValue[0] == '\0' ? NULL : yukhString(accessGroupValue);
	if (service == NULL || account == NULL || (accessGroupValue[0] != '\0' && accessGroup == NULL)) {
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		if (accessGroup != NULL) CFRelease(accessGroup);
		return yukhKeychainUnavailable;
	}
	SecKeychainRef keychain = NULL;
	CFArrayRef searchList = NULL;
	if (!yukhOpenExactKeychain(keychainPath, &keychain, &searchList)) {
		CFRelease(service); CFRelease(account); if (accessGroup != NULL) CFRelease(accessGroup);
		return yukhKeychainUnavailable;
	}
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		CFRelease(service); CFRelease(account); if (accessGroup != NULL) CFRelease(accessGroup);
		yukhReleaseKeychainScope(keychain, searchList);
		return yukhKeychainUnavailable;
	}
	// Two matches distinguish one valid item from every ambiguous cardinality.
	// kSecMatchLimitAll returns errSecParam for this explicit legacy scope.
	int matchLimitValue = 2;
	CFNumberRef matchLimit = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &matchLimitValue);
	if (matchLimit == NULL) {
		CFRelease(query);
		CFRelease(service); CFRelease(account); if (accessGroup != NULL) CFRelease(accessGroup);
		yukhReleaseKeychainScope(keychain, searchList);
		return yukhKeychainUnavailable;
	}
	yukhAddExactQuery(query, service, account, accessGroup, searchList);
	CFDictionarySetValue(query, kSecMatchLimit, matchLimit);
	CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(matchLimit);
	CFRelease(query);
	CFRelease(service); CFRelease(account); if (accessGroup != NULL) CFRelease(accessGroup);
	yukhReleaseKeychainScope(keychain, searchList);
	if (status == errSecItemNotFound) {
		if (result != NULL) CFRelease(result);
		return yukhKeychainAbsent;
	}
	if (status != errSecSuccess) {
		if (result != NULL) CFRelease(result);
		return yukhKeychainUnavailable;
	}
	if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
		if (result != NULL) CFRelease(result);
		return yukhKeychainInvalid;
	}
	CFArrayRef matches = (CFArrayRef)result;
	if (CFArrayGetCount(matches) != 1) {
		CFRelease(result);
		return yukhKeychainInvalid;
	}
	CFTypeRef match = CFArrayGetValueAtIndex(matches, 0);
	if (match == NULL || CFGetTypeID(match) != CFDictionaryGetTypeID()) {
		CFRelease(result);
		return yukhKeychainInvalid;
	}
	CFDictionaryRef attributes = (CFDictionaryRef)match;
	CFTypeRef data = CFDictionaryGetValue(attributes, kSecValueData);
	CFTypeRef returnedService = CFDictionaryGetValue(attributes, kSecAttrService);
	CFTypeRef returnedAccount = CFDictionaryGetValue(attributes, kSecAttrAccount);
	CFTypeRef returnedGroup = CFDictionaryGetValue(attributes, kSecAttrAccessGroup);
	CFTypeRef returnedAccessibility = CFDictionaryGetValue(attributes, kSecAttrAccessible);
	CFTypeRef returnedLabel = CFDictionaryGetValue(attributes, kSecAttrLabel);
	CFStringRef expectedService = yukhString(serviceValue);
	CFStringRef expectedAccount = yukhString(accountValue);
	CFStringRef expectedGroup = accessGroupValue[0] == '\0' ? NULL : yukhString(accessGroupValue);
	CFStringRef expectedLabel = yukhString("Yukh Coordination Root Key");
	// Legacy file Keychains do not expose a kSecAttrAccessible value.
	int valid = data != NULL && returnedService != NULL && returnedAccount != NULL &&
		returnedAccessibility == NULL && returnedLabel != NULL && CFGetTypeID(data) == CFDataGetTypeID() &&
		CFDataGetLength((CFDataRef)data) == 32 && expectedService != NULL && expectedAccount != NULL &&
		expectedLabel != NULL && CFEqual(returnedService, expectedService) &&
		CFEqual(returnedAccount, expectedAccount) &&
		CFEqual(returnedLabel, expectedLabel) &&
		((expectedGroup == NULL && returnedGroup == NULL) ||
		 (expectedGroup != NULL && returnedGroup != NULL && CFEqual(returnedGroup, expectedGroup)));
	if (expectedService != NULL) CFRelease(expectedService);
	if (expectedAccount != NULL) CFRelease(expectedAccount);
	if (expectedGroup != NULL) CFRelease(expectedGroup);
	if (expectedLabel != NULL) CFRelease(expectedLabel);
	if (!valid) {
		CFRelease(result);
		return yukhKeychainInvalid;
	}
	CFDataGetBytes((CFDataRef)data, CFRangeMake(0, 32), output);
	CFRelease(result);
	unsigned char aggregate = 0;
	for (int i = 0; i < 32; i++) aggregate |= output[i];
	if (aggregate == 0) {
		memset(output, 0, 32);
		return yukhKeychainInvalid;
	}
	return yukhKeychainFound;
}

static int yukhKeychainCreate(const char *keychainPath, const char *serviceValue, const char *accountValue,
	const char *accessGroupValue, const unsigned char value[32]) {
	CFStringRef service = yukhString(serviceValue);
	CFStringRef account = yukhString(accountValue);
	CFStringRef accessGroup = accessGroupValue[0] == '\0' ? NULL : yukhString(accessGroupValue);
	CFStringRef label = yukhString("Yukh Coordination Root Key");
	CFDataRef secret = CFDataCreate(kCFAllocatorDefault, value, 32);
	if (service == NULL || account == NULL || label == NULL || secret == NULL ||
		(accessGroupValue[0] != '\0' && accessGroup == NULL)) {
		if (service != NULL) CFRelease(service); if (account != NULL) CFRelease(account);
		if (accessGroup != NULL) CFRelease(accessGroup); if (label != NULL) CFRelease(label);
		if (secret != NULL) CFRelease(secret);
		return yukhKeychainUnavailable;
	}
	SecKeychainRef keychain = NULL;
	CFArrayRef searchList = NULL;
	if (!yukhOpenExactKeychain(keychainPath, &keychain, &searchList)) {
		CFRelease(service); CFRelease(account); if (accessGroup != NULL) CFRelease(accessGroup);
		CFRelease(label); CFRelease(secret);
		return yukhKeychainUnavailable;
	}
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		CFRelease(service); CFRelease(account); if (accessGroup != NULL) CFRelease(accessGroup);
		CFRelease(label); CFRelease(secret);
		yukhReleaseKeychainScope(keychain, searchList);
		return yukhKeychainUnavailable;
	}
	yukhAddExactCreate(query, service, account, accessGroup, keychain);
	CFDictionarySetValue(query, kSecAttrLabel, label);
	CFDictionarySetValue(query, kSecValueData, secret);
	OSStatus status = SecItemAdd(query, NULL);
	CFRelease(query);
	CFRelease(service); CFRelease(account); if (accessGroup != NULL) CFRelease(accessGroup);
	CFRelease(label); CFRelease(secret);
	yukhReleaseKeychainScope(keychain, searchList);
	if (status == errSecSuccess) return yukhKeychainCreated;
	if (status == errSecDuplicateItem) return yukhKeychainAmbiguous;
	return yukhKeychainUnavailable;
}
*/
import "C"

import (
	"context"
	"unsafe"
)

type nativeProvider struct{}

func newNativeProvider() provider { return nativeProvider{} }

func (nativeProvider) Lookup(ctx context.Context, binding Binding) ([]item, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errUnavailable
	}
	keychainPath := C.CString(binding.keychainPath)
	service := C.CString(binding.service)
	account := C.CString(binding.account)
	accessGroup := C.CString(binding.accessGroup)
	defer C.free(unsafe.Pointer(keychainPath))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(accessGroup))
	var key [32]byte
	result := C.yukhKeychainLookup(keychainPath, service, account, accessGroup, (*C.uchar)(unsafe.Pointer(&key[0])))
	if ctx.Err() != nil {
		clear(key[:])
		return nil, errUnavailable
	}
	switch result {
	case C.yukhKeychainAbsent:
		return nil, nil
	case C.yukhKeychainFound:
		return []item{{service: binding.service, account: binding.account, accessGroup: binding.accessGroup,
			accessibility: rootItemAccessibility, label: rootItemLabel, secret: append([]byte(nil), key[:]...)}}, nil
	default:
		clear(key[:])
		return nil, errUnavailable
	}
}

func (nativeProvider) Create(ctx context.Context, binding Binding, value []byte) (bool, error) {
	if ctx == nil || ctx.Err() != nil || len(value) != 32 || isZero(value) {
		return false, errUnavailable
	}
	keychainPath := C.CString(binding.keychainPath)
	service := C.CString(binding.service)
	account := C.CString(binding.account)
	accessGroup := C.CString(binding.accessGroup)
	defer C.free(unsafe.Pointer(keychainPath))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(accessGroup))
	result := C.yukhKeychainCreate(keychainPath, service, account, accessGroup, (*C.uchar)(unsafe.Pointer(&value[0])))
	if ctx.Err() != nil {
		return false, errUnavailable
	}
	switch result {
	case C.yukhKeychainCreated:
		return false, nil
	case C.yukhKeychainAmbiguous:
		return true, errUnavailable
	default:
		return false, errUnavailable
	}
}
