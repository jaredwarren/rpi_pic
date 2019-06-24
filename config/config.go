package config

import (
	bolt "go.etcd.io/bbolt"
)

// Load ...
func Load(path string) (config *Config, err error) {
	config = &Config{}
	db, err := bolt.Open(path, 0666, nil)
	if err != nil {
		panic(err.Error())
	}
	// defer db.Close()
	config.DB = db

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("config"))
		return err
	})
	if err != nil {
		panic(err.Error())
	}

	return
}

// Config ...
type Config struct {
	DB *bolt.DB
}

// Set ...
func (us *Config) Set(key, value string) error {
	return us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		return b.Put([]byte(key), []byte(value))
	})
}

// Get ...
func (us *Config) Get(key string) string {
	v := ""
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		v = string(b.Get([]byte(key)))
		return nil
	})
	return v
}

// GetBool ...
func (us *Config) GetBool(key string) bool {
	br := false
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		v := b.Get([]byte(key))
		if len(v) > 0 {
			br = true
		}
		return nil
	})
	return br
}

// Delete ...
func (us *Config) Delete(key string) (err error) {
	return us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		return b.Delete([]byte(key))
	})
}
