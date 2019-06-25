package user

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jaredwarren/rpi_pic/app"
)

func TestRegisterHandler(t *testing.T) {

	os.Remove("./user_test.db")

	// db setup
	userStore, err := NewStore("./user_test.db")
	if err != nil {
		panic(err.Error())
	}

	token := "token_asdf1234"
	userStore.SetToken("jlwarren1@gmail.com", token)

	// service setup
	service := app.New("Shipping")
	uc := NewUserController(service, userStore)

	// setup request
	req := httptest.NewRequest(http.MethodPost, "/user/register", strings.NewReader(fmt.Sprintf("password1=asdf&password2=asdf&username=%s&token=%s", "jlwarren1%40gmail.com", token)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// make request
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(uc.RegisterHandler)
	handler.ServeHTTP(rr, req)

	// Check results
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// assume ID is 1
	if rr.Header().Get("Location") != "/user/1/picture" {
		t.Errorf("handler returned unexpected location: got %v want %v", rr.Header().Get("Location"), "/user/1/picture")
	}
}
