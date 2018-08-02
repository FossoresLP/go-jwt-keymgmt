package validator

// ErrInternalError signalizes something connection related failed.
type ErrInternalError string

func (e ErrInternalError) Error() string {
	return "internal error"
}

// ErrTokenInvalid signalizes an invalid JWT.
type ErrTokenInvalid string

func (e ErrTokenInvalid) Error() string {
	return "token invalid"
}

// ErrKeyserverAddrNotSet signalizes that the JWT has no key URL embedded and can therefore not be validated.
type ErrKeyserverAddrNotSet string

func (e ErrKeyserverAddrNotSet) Error() string {
	return "keyserver address not set"
}
