package user

// User holds a users account information
type User struct {
	ID            string
	Username      string
	Password      string
	Authenticated bool
	Token         string
}
