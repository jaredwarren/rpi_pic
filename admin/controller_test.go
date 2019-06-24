package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jaredwarren/rpi_pic/user"

	"github.com/jaredwarren/rpi_pic/app"
)

func TestInviteHandler(t *testing.T) {
	// db setup
	userStore, err := user.NewStore("./user_test.db")
	if err != nil {
		panic(err.Error())
	}

	// service setup
	service := app.New("Shipping_Test")
	ac := NewAdminController(service, userStore)

	// setup request
	req := httptest.NewRequest(http.MethodPost, "/admin/user/invite", strings.NewReader(fmt.Sprintf("username=%s", "jlwarren1%40gmail.com")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// make request
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(ac.InviteHandler)
	handler.ServeHTTP(rr, req)

	// Check results
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if rr.Header().Get("Location") != "/admin/user" {
		t.Errorf("handler returned unexpected location: got %v want %v", rr.Header().Get("Location"), "/user/1/picture")
	}

	// check token
	ut, _ := userStore.GetToken("jlwarren1@gmail.com")
	if ut != "" {
		t.Errorf("missing token: %s", ut)
	}

}
