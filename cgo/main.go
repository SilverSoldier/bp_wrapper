package main

// Go []byte slice to C array
// The C array is allocated in the C heap using malloc.
// It is the caller's responsibility to arrange for it to be
// freed, such as by calling C.free (be sure to include stdlib.h
// if C.free is needed).
// func C.CBytes([]byte) unsafe.Pointer

// C data with explicit length to Go []byte
// func C.GoBytes(unsafe.Pointer, C.int) []byte

import (
	// #cgo LDFLAGS: -pthread -lbp_wrapper -lm -ldl
	// #include "bp.h"
	// #include <stdlib.h>
	"C"
)
import (
	"fmt"
	"unsafe"
)

func test_add_commitment() {
	val10 := (*C.char)(C.calloc(32, C.sizeof_char))
	val20 := (*C.char)(C.calloc(32, C.sizeof_char))
	zero := (*C.char)(C.calloc(32, C.sizeof_char))
	comm10 := (*C.char)(C.calloc(32, C.sizeof_char))
	exp_comm20 := (*C.char)(C.calloc(32, C.sizeof_char))
	act_comm20 := (*C.char)(C.calloc(32, C.sizeof_char))

	defer C.free(unsafe.Pointer(val10))
	defer C.free(unsafe.Pointer(val20))
	defer C.free(unsafe.Pointer(zero))
	defer C.free(unsafe.Pointer(comm10))
	defer C.free(unsafe.Pointer(exp_comm20))
	defer C.free(unsafe.Pointer(act_comm20))

	C.gen_commitment(val10, zero, comm10)

	C.gen_commitment(val20, zero, exp_comm20)

	C.add_commitment(comm10, comm10, 0, act_comm20)

}

func test_mult_commitment() bool {
	gval10 := make([]byte, 32)
	gval20 := make([]byte, 32)
	gzero := make([]byte, 32)

	ccomm10 := (*C.char)(C.calloc(32, C.sizeof_char))
	cexp_comm20 := (*C.char)(C.calloc(32, C.sizeof_char))
	cact_comm20 := (*C.char)(C.calloc(32, C.sizeof_char))

	defer C.free(unsafe.Pointer(ccomm10))
	defer C.free(unsafe.Pointer(cexp_comm20))
	defer C.free(unsafe.Pointer(cact_comm20))

	gval10[0] = 10
	gval20[0] = 20

	C.gen_commitment((*C.char)(C.CBytes(gval10)), (*C.char)(C.CBytes(gzero)), ccomm10)
	C.gen_commitment((*C.char)(C.CBytes(gval20)), (*C.char)(C.CBytes(gzero)), cexp_comm20)
	C.mult_commitment(ccomm10, 2, cact_comm20)

	// Convert the C values of the variables that should be read to Go
	gexp_comm20 := C.GoBytes((unsafe.Pointer)(cexp_comm20), 32)
	gact_comm20 := C.GoBytes((unsafe.Pointer)(cact_comm20), 32)

	for i := 0; i < 32; i++ {
		if gexp_comm20[i] != gact_comm20[i] {
			return false
		}
	}
	return true
}

func main() {
	if test_mult_commitment() {
		fmt.Println("Passed")
	} else {
		fmt.Println("Failed")
	}
}
