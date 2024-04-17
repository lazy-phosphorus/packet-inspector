package exception

type CgoException struct {
	message string
}

func NewCgoException(message string) error {
	exception := new(CgoException)
	exception.message = message
	return exception
}

func (exception *CgoException) Error() string {
	return exception.message
}
