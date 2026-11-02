package service

// ValidationError reports a request or account-state problem the caller has to
// fix. Every other error returned by the services is an upstream, protocol or
// storage failure.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

func inputError(message string) error { return &ValidationError{Message: message} }
