package utils

/* #include "strerror.h" */
import "C"

func Strerror() string {
	temp := C.Strerror()
	return C.GoStringN(temp.message, temp.length)
}
