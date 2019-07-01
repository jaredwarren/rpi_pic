package config

import (
	"fmt"
	"os"
	"testing"
)

func TestGetSet(t *testing.T) {
	os.Remove("./config_test.db")
	cs, err := Load("./config_test.db")
	if err != nil {
		t.Fatal(err)
	}

	{
		testIn := "testv"
		cs.Set("tests", testIn)

		testOut := cs.Get("tests")

		if testOut != testIn {
			t.Error("wrong values:", testOut, "!=", testIn)
		}
	}

	// Test String
	{
		testIn := "testv"
		cs.Set("tests", testIn)

		testOut := cs.Get("tests")

		if testOut != testIn {
			t.Error("wrong values:", testOut, "!=", testIn)
		}
	}

	// Test Int
	{
		testIn := 124
		cs.Set("tests", testIn)

		testOut := cs.Get("tests")

		if testOut != testIn {
			t.Error("wrong values:", testOut, "!=", testIn)
		}
	}

	// Test bool
	{
		testIn := true
		cs.Set("tests", testIn)

		testOut := cs.Get("tests")

		if testOut != testIn {
			t.Error("wrong values:", testOut, "!=", testIn)
		}
	}
}

func TestFetchAll(t *testing.T) {
	os.Remove("./config_test.db")
	cs, err := Load("./config_test.db")
	if err != nil {
		t.Fatal(err)
	}

	cs.Set("test1", "test1")
	cs.Set("test2", 4)
	cs.Set("test3", false)

	all := cs.FetchAll()
	fmt.Printf("%+v\n", all)

	if all["test1"] != "test1" {
		t.Error("wrong values:", all["test1"], "!=", "test1")
	}

	if all["test2"] != 4 {
		t.Error("wrong values:", all["test2"], "!=", "4")
	}

	if all["test3"] != false {
		t.Error("wrong values:", all["test3"], "!=", "false")
	}
}
