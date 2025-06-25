package rustblokk

/*

#include <stdlib.h>
#include "wireguard_rust.h"

*/
import "C"
import "unsafe"

func ContcatStrAndInt(str string, i int) string {
	// allocate C string
	cstr := C.CString(str)

	// use C's free for C-allocated memory
	defer C.free(unsafe.Pointer(cstr))

	// call Rust function
	result := C.concat_string_and_number(cstr, C.int(i))

	// use Rust's deallocator for Rust-allocated memory
	defer C.free_string(result)

	// convert to Go string
	return C.GoString(result)
}
