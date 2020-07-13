package idam

import (
	"context"
	//"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	//"strconv"
	"encoding/base64"
	"encoding/json"
	//"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

type Config struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`

	//Scopes []string `json:"scopes"` // defaults to "profile" and "email"
}

//type CallbackConfig struct{}

// Open returns an authentication strategy which requires no user interaction.
//func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
//	return NewCallbackConnector(logger), nil
//}

// Open returns a strategy for logging in through GitHub.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	i := idamConnector{
		redirectURI:  c.RedirectURI,
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		logger:       logger,
	}

	return &i, nil
}

var (
	_ connector.CallbackConnector = (*idamConnector)(nil)
)

type idamConnector struct {
	redirectURI  string
	clientID     string
	clientSecret string
	logger       log.Logger
}

type Temp struct {
 accessToken string 
 idToken string
 Urlval string `json:"url"`
}

func (c *idamConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
    tokenendpoint,err := c.getEndpoint()
	fmt.Println("tokenendpoint is %s", tokenendpoint)
	fmt.Println(err)
	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenendpoint,
		},
		RedirectURL: c.redirectURI,
	}
}

func (c *idamConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
fmt.Println("test156",state)
fmt.Println("test256",callbackURL)
	//if c.redirectURI != callbackURL {
	fmt.Println("test256678")
		//return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	//}
fmt.Println("ftttttttttttttttttt", scopes)
u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()
	fmt.Println("u----",u.String())
	return u.String(), nil
	//return c.oauth2Config(scopes).AuthCodeURL(state), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *idamConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
fmt.Println("handle callback")
	q := r.URL.Query()
	fmt.Println("handle callback66", q)
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	oauth2Config := c.oauth2Config(s)
    fmt.Println("handle callback66sd", oauth2Config)
	ctx := r.Context()

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	fmt.Println("handle--callback", token)
	if err != nil {
		return identity, fmt.Errorf("github: failed to get token: %v", err)
    }

	//client := oauth2Config.Client(ctx, token)
    tokenendpoint,err := c.getEndpoint()
	fmt.Println("tokenendpoint is %s", tokenendpoint)
	fmt.Println("err is %s", err)
	cli := &http.Client{}
	req, err23 := http.NewRequest("GET", tokenendpoint, nil)
	rsp5786, err127 := cli.Do(req)
	fmt.Println(rsp5786.Body)
	bodys2, err256 := ioutil.ReadAll(rsp5786.Body)
	fmt.Println(string(bodys2))
	fmt.Println("err34..",err23)
	fmt.Println("err34..",err256)
	fmt.Println("err34..",err127)
	
	//user, err := c.user(ctx, client)
	//fmt.Println("printing user %s",user)
	//if err != nil {
	//	return identity, fmt.Errorf("github: get user: %v", err)
	//}

	//username := "user.Name"
	//if username == "" {
	//	username = "user.Login"
	//}

	identity = connector.Identity{
		UserID:            "meenaksi55",
		Username:          "meenk2323",
		PreferredUsername: "ejfehf",
		Email:             "meeenakshi.chaudhary@pwc.com",
		EmailVerified:     true,
	}
	

	return identity, nil
}


func (c *idamConnector) getEndpoint() (string,error){
    var (
		url1      = "https://analyticapps.hosting.pwc.com/usermgmt-demo/idam/auth?fromApp=xip-dev-dex"
		username = "XIP"
		password = "e437591b9350e533ad366664afae99e1"
	)
	fmt.Println("test28989898897878")
	authtoken := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	println(authtoken)
	cli := &http.Client{}
	req, err := http.NewRequest("GET", url1, nil)
	req.Header.Set("Authorization", "Basic "+authtoken)
	fmt.Println("req........%s",req)
	rsp, err := cli.Do(req)
		fmt.Println("rsp tytyt %s",rsp)
	if err != nil {
		fmt.Println(err)
	}

	body, err := ioutil.ReadAll(rsp.Body)
	fmt.Println("body is %s", string(body))
	tempdata := Temp{}
	err = json.Unmarshal(body, &tempdata)
	fmt.Println("etseifuefwef....",tempdata.Urlval)
	decodedValue, err := url.QueryUnescape(tempdata.Urlval)
	fmt.Println("decodedvlauefeewfw %s",decodedValue)
	
	//var u user
	
	return decodedValue, nil


}

func (c *idamConnector) user(ctx context.Context, client *http.Client) (string, error) {
	// https://developer.github.com/v3/users/#get-the-authenticated-user
	
	var (
		url1      = "https://analyticapps.hosting.pwc.com/usermgmt-demo/idam/auth?fromApp=xip-dev-dex"
		username = "XIP"
		password = "e437591b9350e533ad366664afae99e1"
	)
	
	authtoken := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	println(authtoken)
	cli := &http.Client{}
	req, err := http.NewRequest("GET", url1, nil)
	req.Header.Set("Authorization", "Basic "+authtoken)
	fmt.Println("req........%s",req)
	rsp, err := cli.Do(req)
		fmt.Println("rsp tytyt %s",rsp)
	if err != nil {
		fmt.Println(err)
	}

	body, err := ioutil.ReadAll(rsp.Body)
	fmt.Println("body is %s", string(body))
	tempdata := Temp{}
	err = json.Unmarshal(body, &tempdata)
	fmt.Println("etseifuefwef....",tempdata.Urlval)
	decodedValue, err := url.QueryUnescape(tempdata.Urlval)
	fmt.Println("decodedvlauefeewfw %s",decodedValue)
	
	//var u user
	
	return decodedValue, nil
}
