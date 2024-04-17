package exception

type InvalidArgsException struct {
	message string
}

func NewInvalidArgsException(message string) error {
	excpetion := new(InvalidArgsException)
	excpetion.message = message
	return excpetion
}

func (exception *InvalidArgsException) Error() string {
	return exception.message
}
