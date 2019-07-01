package config

import (
	"bytes"
	"encoding/gob"
	"reflect"

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
		_, err = tx.CreateBucketIfNotExists([]byte("config_type"))
		return err
	})
	if err != nil {
		panic(err.Error())
	}

	// set default configs
	config.Set("email", false)
	config.Set("pictureURL", "http://localhost:8081/")
	config.Set("time_per_picture", 30)

	return
}

// Config ...
type Config struct {
	DB *bolt.DB
}

func gobEncode(ci interface{}) []byte {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	enc.Encode(ci)
	return buf.Bytes()
}

// Set ...
func (us *Config) Set(key string, value interface{}) error {
	return us.DB.Update(func(tx *bolt.Tx) error {
		// store type
		bt := tx.Bucket([]byte("config_type"))
		vType := reflect.TypeOf(value).String()
		bt.Put([]byte(key), []byte(vType))

		// store value
		b := tx.Bucket([]byte("config"))
		return b.Put([]byte(key), gobEncode(value))
	})
}

// Get TODO: fix this..
func (us *Config) Get(key string) (v interface{}) {
	us.DB.View(func(tx *bolt.Tx) error {
		// get type
		bt := tx.Bucket([]byte("config_type"))
		vType := string(bt.Get([]byte(key)))

		// get value
		b := tx.Bucket([]byte("config"))
		data := b.Get([]byte(key))

		// decode
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		var err error
		switch vType {
		case "string":
			x := ""
			err = dec.Decode(&x)
			v = x
		case "bool":
			x := false
			err = dec.Decode(&x)
			v = x
		case "int":
			x := 0
			err = dec.Decode(&x)
			v = x
		}

		return err
	})
	return
}

// GetVar ...
func (us *Config) GetVar(key string, v interface{}) {
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		data := b.Get([]byte(key))

		// decode
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		return dec.Decode(v)
	})
	return
}

// FetchAll ...
func (us *Config) FetchAll() map[string]interface{} {
	result := map[string]interface{}{}
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// get type
			bt := tx.Bucket([]byte("config_type"))
			vType := string(bt.Get([]byte(k)))
			key := string(k)

			// decode
			buf := bytes.NewBuffer(v)
			dec := gob.NewDecoder(buf)
			switch vType {
			case "string":
				x := ""
				dec.Decode(&x)
				result[key] = x
			case "bool":
				x := false
				dec.Decode(&x)
				result[key] = x
			case "int":
				x := 0
				dec.Decode(&x)
				result[key] = x
			}
		}
		return nil
	})
	return result
}

// Delete ...
func (us *Config) Delete(key string) (err error) {
	return us.DB.Update(func(tx *bolt.Tx) error {
		bt := tx.Bucket([]byte("config_type"))
		bt.Delete([]byte(key))
		b := tx.Bucket([]byte("config"))
		return b.Delete([]byte(key))
	})
}
