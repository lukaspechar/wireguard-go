package rustblokk

/*

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "vpnpacketfilter_ios.h"

*/
import "C"
import (
	"unsafe"
)

func RustInitLogger() {
	C.rust_init_logger()
}

// initial config values
func SetBlokkDatabase(path string) {

	cstr := C.CString(path)

	// use C's free for C-allocated memory
	defer C.free(unsafe.Pointer(cstr))

	C.set_blokk_database(cstr)
}

func SetCountryDatabase(path string) {

	cstr := C.CString(path)

	// use C's free for C-allocated memory
	defer C.free(unsafe.Pointer(cstr))

	C.set_country_database(cstr)
}
func SetCacheLocation(location string) {

	cstr := C.CString(location)

	// use C's free for C-allocated memory
	defer C.free(unsafe.Pointer(cstr))

	C.set_cache_location(cstr)
}

func SetIPBlocked(blocked bool) {
	C.set_ip_blocked(C.bool(blocked))
}

func SetUTF8Blocked(blocked bool) {
	C.set_utf8_blocked(C.bool(blocked))
}

func IsPaused() bool {
	return bool(C.is_paused())
}

// sets user whitelist in vpnpacketfilter_ios
func SetUserWhitelist(list []string) {
	// Convert Go []string to []*C.char
	cStrings := make([]*C.char, len(list))
	for i, s := range list {
		cStrings[i] = C.CString(s)
	}

	// ensure memory is freed after use
	defer func() {
		for _, s := range cStrings {
			C.free(unsafe.Pointer(s))
		}
	}()

	// get pointer to first element
	cList := (**C.char)(unsafe.Pointer(&cStrings[0]))
	cLen := C.uintptr_t(len(list))

	// call C function
	C.set_user_whitelist(cList, cLen)
}

// sets user backlist in vpnpacketfilter_ios
func SetUserBlackList(list []string) {
	// Convert Go []string to []*C.char
	cStrings := make([]*C.char, len(list))
	for i, s := range list {
		cStrings[i] = C.CString(s)
	}

	// ensure memory is freed after use
	defer func() {
		for _, s := range cStrings {
			C.free(unsafe.Pointer(s))
		}
	}()

	// get pointer to first element
	cList := (**C.char)(unsafe.Pointer(&cStrings[0]))
	cLen := C.uintptr_t(len(list))

	// call C function
	C.set_user_blacklist(cList, cLen)
}

// sets filter enabled lists in vpnpacketfilter_ios
func SetEnabledLists(list []string) {
	// Convert Go []string to []*C.char
	cStrings := make([]*C.char, len(list))
	for i, s := range list {
		cStrings[i] = C.CString(s)
	}

	// ensure memory is freed after use
	defer func() {
		for _, s := range cStrings {
			C.free(unsafe.Pointer(s))
		}
	}()

	// get pointer to first element
	cList := (**C.char)(unsafe.Pointer(&cStrings[0]))
	cLen := C.uintptr_t(len(list))

	// call C function
	C.set_enabled_lists(cList, cLen)
}

// sets silent domains in vpnpacketfilter_ios
func SetSilentDomains(list []string) {
	// Convert Go []string to []*C.char
	cStrings := make([]*C.char, len(list))
	for i, s := range list {
		cStrings[i] = C.CString(s)
	}

	// ensure memory is freed after use
	defer func() {
		for _, s := range cStrings {
			C.free(unsafe.Pointer(s))
		}
	}()

	// get pointer to first element
	cList := (**C.char)(unsafe.Pointer(&cStrings[0]))
	cLen := C.uintptr_t(len(list))

	// call C function
	C.set_silent_domains(cList, cLen)
}

// sets the aggressive mode for filters in vpnpacketfilter_ios
func SetAggressiveMode(isAggressive bool) {
	C.set_aggressive_mode(C.bool(isAggressive))
}

func ShouldBlockPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	/*
		C.int32_t is a typedef for int32_t, but in cgo, int32_t is mapped to C.int32_t
		and uint8_t* is mapped to *C.uint8_t, but for byte slices, you can use unsafe.Pointer
		However, for const uint8_t*, *C.uchar is most compatible.
		Using *C.uchar is safest in practice:
	*/
	cPacket := (*C.uchar)(unsafe.Pointer(&packet[0]))
	cLen := C.int32_t(len(packet))
	result := C.should_block_packet(cPacket, cLen)
	return bool(result)

	// cPacket := C.CBytes(packet)
	// defer C.free(cPacket)
	// result := C.should_block_packet((*C.uchar)(cPacket), C.int32_t(len(packet)))
	// return bool(result)
}

func ParseInPacket(packet []byte) {
	if len(packet) == 0 {
		return
	}
	// C.int32_t is a typedef for int32_t, but in cgo, int32_t is mapped to C.int32_t
	// and uint8_t* is mapped to *C.uint8_t, but for byte slices, you can use unsafe.Pointer
	// However, for const uint8_t*, *C.uchar is most compatible.
	// Using *C.uchar is safest in practice:
	cPacket := (*C.uchar)(unsafe.Pointer(&packet[0]))
	cLen := C.int32_t(len(packet))
	C.parse_in_packet(cPacket, cLen)
}

func ReloadBlockedCountries() {
	C.reload_blocked_countries()
}
