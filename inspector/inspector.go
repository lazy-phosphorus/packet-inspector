package inspector

/* #include "inspector.h" */
import "C"
import (
	"packet-inspector/exception"
	"packet-inspector/utils"
	"syscall"
)

type Inspector struct {
	fd     int
	buffer []byte
}

func NewInspector(bufferSize int) *Inspector {
	inspector := new(Inspector)
	inspector.buffer = make([]byte, bufferSize)
	return inspector
}

func (inspector *Inspector) Open() error {
	fd := int(C.GetFileDescriptor())
	if fd == -1 {
		return exception.NewCgoException(utils.Strerror())
	}
	inspector.fd = fd
	return nil
}

func (inspector *Inspector) Close() error {
	return syscall.Close(inspector.fd)
}

func (inspector *Inspector) Read() ([]byte, error) {
	if inspector.fd == -1 {
		return nil, exception.NewInvalidArgsException("Invalid file descriptor")
	}
	length, err := syscall.Read(inspector.fd, inspector.buffer)
	if err != nil {
		return nil, exception.NewCgoException(utils.Strerror())
	}

	result := make([]byte, length)
	copy(result, inspector.buffer)
	return result, nil
}
