package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jaredwarren/rpi_pic/admin"
	"github.com/jaredwarren/rpi_pic/user"

	"github.com/jaredwarren/rpi_pic/app"
)

func TestAll(t *testing.T) {

	os.Remove("./user_test.db")
	os.Remove("./Shipping_Test_config.db")

	// db setup
	userStore, err := user.NewStore("./user_test.db")
	if err != nil {
		panic(err.Error())
	}

	// service setup
	service := app.New("Shipping_Test")
	uc := user.NewUserController(service, userStore)
	ac := admin.NewAdminController(service, userStore)

	username := "jlwarren1@gmail.com"
	token := ""
	password := "asdf1234"

	//
	// INVITE
	//
	{
		// setup request
		req := httptest.NewRequest(http.MethodPost, "/admin/user/invite", strings.NewReader(fmt.Sprintf("username=%s", username)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// make request
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(ac.InviteHandler)
		handler.ServeHTTP(rr, req)

		// Check results
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// check token
		u, err := userStore.Get(username)
		if err != nil {
			t.Errorf(err.Error())
		}
		if u == nil {
			t.Errorf("User missing")
		}
		if u.Token == "" {
			t.Errorf("missing token: %+v", u)
		}
		token = u.Token
	}

	//
	// REGISTER
	//
	{
		// setup request
		req := httptest.NewRequest(http.MethodPost, "/user/register", strings.NewReader(fmt.Sprintf("username=%s&token=%s&password1=%s&password2=%s", username, token, password, password)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// make request
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(uc.RegisterHandler)
		handler.ServeHTTP(rr, req)

		// Check results
		if status := rr.Code; status != http.StatusFound {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
		}

		if rr.Header().Get("Location") != fmt.Sprintf("/user/%s/picture", username) {
			t.Errorf("handler returned unexpected location: got %v want %v", rr.Header().Get("Location"), fmt.Sprintf("/user/%s/picture", username))
		}
	}

}
