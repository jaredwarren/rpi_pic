package config

import (
	"bytes"
	"encoding/gob"
	"fmt"
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

func gobEncode(ci interface{}) []byte {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	enc.Encode(ci)
	return buf.Bytes()
}

func gobDecodeBool(data []byte) (bool, error) {
	var ci bool
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&ci)
	if err != nil {
		return false, err
	}
	return ci, nil
}

func gobDecodeString(data []byte) (string, error) {
	var ci string
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&ci)
	if err != nil {
		return "", err
	}
	return ci, nil
}

// Set ...
func (us *Config) Set(key string, value interface{}) error {
	return us.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		return b.Put([]byte(key), gobEncode(value))
	})
}

// Get ...
func (us *Config) Get(key string, v interface{}) {
	us.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("config"))
		data := b.Get([]byte(key))

		// decode
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)

		// TODO: figure out if i can return an interface{}   >>>  x := config.Get("mykey").(string)
		r := reflect.ValueOf(v)
		fmt.Println(r.String())

		return dec.Decode(v)
	})

}

// FetchAll ...
func (us *Config) FetchAll() []string {

	// us.DB.View(func(tx *bolt.Tx) error {
	// 	b := tx.Bucket([]byte("users"))
	// 	c := b.Cursor()
	// 	for k, v := c.First(); k != nil; k, v = c.Next() {
	// 		json.Unmarshal(v, u)
	// 		r := reflect.ValueOf(u)
	// 		f := reflect.Indirect(r).FieldByName(key)
	// 		if f.String() == value {
	// 			return nil
	// 		}
	// 	}
	// 	return nil
	// })
	return nil
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
