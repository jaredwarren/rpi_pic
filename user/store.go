package user

import (
	"encoding/json"
	"reflect"
	"strconv"

	bolt "go.etcd.io/bbolt"
)

// NewStore ...
func NewStore(path string) (store *Store, err error) {
	store = &Store{}
	db, err := bolt.Open(path, 0666, nil)
	if err != nil {
		panic(err.Error())
	}
	// defer db.Close()
	store.DB = db

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("users"))
		return err
	})
	if err != nil {
		panic(err.Error())
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("token"))
		return err
	})
	if err != nil {
		panic(err.Error())
	}

	return
}

// Store ...
type Store struct {
	DB *bolt.DB
}

// Save ...
func (us *Store) Save(u *User) error {
	return us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))

		// look for exsisting user
		var err error
		v := b.Get([]byte(u.Username))
		if len(v) > 0 {
			err = json.Unmarshal(v, u)
		} else {
			// new user add ID
			var id uint64
			id, err = b.NextSequence()
			u.ID = strconv.FormatUint(id, 10)
		}

		buf, err := json.Marshal(u)
		if err != nil {
			return err
		}

		return b.Put([]byte(u.Username), buf)
	})
}

// Get ...
func (us *Store) Get(username string) (u *User, err error) {
	u = &User{}
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(username))
		if len(v) > 0 {
			err = json.Unmarshal(v, u)
		}
		return nil
	})
	if u.Username == "" {
		return nil, nil
	}
	return
}

// Find ...
func (us *Store) Find(key, value string) (u *User, err error) {
	u = &User{}
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			json.Unmarshal(v, u)
			r := reflect.ValueOf(u)
			f := reflect.Indirect(r).FieldByName(key)
			if f.String() == value {
				return nil
			}
		}
		return nil
	})
	if u.ID == "" {
		return nil, nil
	}
	return
}

// FetchAll ...
func (us *Store) FetchAll() (users []*User, err error) {
	err = us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			u := &User{}
			if len(v) == 0 {
				u = nil
			} else {
				err = json.Unmarshal(v, u)
			}
			users = append(users, u)
		}
		return err
	})
	return
}

// Delete ...
func (us *Store) Delete(username string) (err error) {
	err = us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		return b.Delete([]byte(username))
	})
	return
}

// GetToken ...
func (us *Store) GetToken(key string) string {
	// find user
	u := &User{}
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(key))
		var err error
		if len(v) > 0 {
			err = json.Unmarshal(v, u)
		}
		return err
	})
	return u.Token
}

// SetToken ...
func (us *Store) SetToken(key, value string) (err error) {
	u := &User{
		Username: key,
	}
	return us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))

		// find user
		v := b.Get([]byte(key))
		var err error
		if len(v) > 0 {
			err = json.Unmarshal(v, u)
		} else {
			// new user add ID
			var id uint64
			id, err = b.NextSequence()
			u.ID = strconv.FormatUint(id, 10)
		}

		// set token
		u.Token = value

		// update user
		var buf []byte
		buf, err = json.Marshal(u)
		if err != nil {
			return err
		}

		return b.Put([]byte(u.Username), buf)
	})
}

// DeleteToken ...
func (us *Store) DeleteToken(key string) (err error) {
	u := &User{}
	return us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))

		// find user
		v := b.Get([]byte(key))
		var err error
		if len(v) > 0 {
			err = json.Unmarshal(v, u)
		} else {
			return nil
		}

		// set token to string "0" value
		u.Token = ""

		// update user
		var buf []byte
		buf, err = json.Marshal(u)
		if err != nil {
			return err
		}

		return b.Put([]byte(u.Username), buf)
	})
}
