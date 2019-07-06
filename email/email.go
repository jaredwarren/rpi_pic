package email

// Email ...
type Email struct {
	To      []string
	From    []string
	Subject string
	Text    string
	HTML    string
}

// Sender ...
type Sender interface {
	Send() (string, error)
}

// Send ...
func (e *Email) Send() (res string, err error) {
	return "", nil
}

// TODO:
