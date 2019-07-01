package config

import (
	"testing"
)

func TestGetSet(t *testing.T) {

	cs, err := Load("./config_test.db")
	if err != nil {
		t.Fatal(err)
	}

	// Test Interface
	{
		testIn := 124
		cs.Set("tests", testIn)

		// var testOut interface{}
		testOut := cs.Get("tests")

		if testOut != testIn {
			t.Errorf("wrong values:%+v != %+v", testOut, testIn)
		}
	}

	// Test String
	{
		testIn := "testv"
		cs.Set("tests", testIn)

		// var testOut string
		testOut := cs.Get("tests")

		if testOut != testIn {
			t.Error("wrong values:", testOut, "!=", testIn)
		}
	}

	// // Test Int
	// {
	// 	testIn := 124
	// 	cs.Set("tests", testIn)

	// 	var testOut int
	// 	cs.Get("tests", &testOut)

	// 	if testOut != testIn {
	// 		t.Error("wrong values:", testOut, "!=", testIn)
	// 	}
	// }

	// // Test bool
	// {
	// 	testIn := true
	// 	cs.Set("tests", testIn)

	// 	var testOut bool
	// 	cs.Get("tests", &testOut)

	// 	if testOut != testIn {
	// 		t.Error("wrong values:", testOut, "!=", testIn)
	// 	}
	// }

}
