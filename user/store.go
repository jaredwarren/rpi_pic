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
func (us *Store) Save(u *User) (ID string, err error) {
	err = us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))

		var id uint64
		id, err = b.NextSequence()
		ID = strconv.FormatUint(id, 10)
		u.ID = ID

		var buf []byte
		buf, err = json.Marshal(u)
		if err != nil {
			return err
		}

		return b.Put([]byte(u.ID), buf)
	})
	return
}

// Update ...
func (us *Store) Update(u *User) (err error) {
	err = us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))

		var buf []byte
		buf, err = json.Marshal(u)
		if err != nil {
			return err
		}
		return b.Put([]byte(u.ID), buf)
	})
	return
}

// Get ...
func (us *Store) Get(ID string) (u *User, err error) {
	u = &User{}
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		v := b.Get([]byte(ID))
		if len(v) == 0 {
			u = nil
		} else {
			err = json.Unmarshal(v, u)
		}
		return nil
	})
	if u.ID == "" {
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
func (us *Store) Delete(ID string) (err error) {
	err = us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		return b.Delete([]byte(ID))
	})
	return
}

// GetToken ...
func (us *Store) GetToken(key string) (v string, err error) {
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("token"))
		v = string(b.Get([]byte(key)))
		return nil
	})
	return
}

// SetToken ...
func (us *Store) SetToken(key, value []byte) (err error) {
	err = us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("token"))
		return b.Put(key, value)
	})
	return
}

// DeleteToken ...
func (us *Store) DeleteToken(key string) (err error) {
	return us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("token"))
		return b.Delete([]byte(key))
	})
}
