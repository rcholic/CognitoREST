package services

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cogIdp "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	jwt "github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

// AWSCognito methods interface
type AWSCognito interface {
	Init() error
	SecretHash(string) string
	SignUp(string, string, string, string) (*cogIdp.SignUpOutput, error)
	SignIn(string, string) (*cogIdp.InitiateAuthOutput, error)
	GetUser(string) (*cogIdp.AdminGetUserOutput, error)
	ConfirmSignUp(string) (*cogIdp.ConfirmSignUpOutput, error)
	ValidateToken(string, map[string]JWKKey) error
	ForgotPassword(string) (*cogIdp.ForgotPasswordOutput, error)
	ConfirmForgotPassword(string, string, string) (*cogIdp.ConfirmForgotPasswordOutput, error)
	ChangePassword(string, string, string) (*cogIdp.ChangePasswordOutput, error)
}

/**
see Using ID Tokens and Access Tokens in your Web APIs:
https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html

decode and verify the sitnature of Cognito JSON web key token:
https://aws.amazon.com/premiumsupport/knowledge-center/decode-verify-cognito-json-token/

verify token example: https://github.com/mura123yasu/go-cognito/blob/master/verifyToken.go

Email and phone verification: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html
*/
// CognitoClient is an empty structure
type CognitoClient struct{}

// JWKKey is JSON web key specific for the cognito region and userpoolId
type JWKKey struct {
	Alg string
	E   string
	Kid string
	Kty string
	N   string
	Use string
}

// JWK is json data struct for JSON Web Key
type JWK struct {
	Keys []JWKKey
}

var (
	// Region for the AWS Cognito service
	region string
	// Client ID for AWS Cognito
	clientID string
	// Client Secret for AWS Cognito
	clientSecret string
	// UserPool ID for AWS Cognito
	userpoolID string

	// Cognito IDP client
	idpClient *cogIdp.CognitoIdentityProvider

	jwkURL string

	// key: kid, value: jwkkey
	// see https://aws.amazon.com/premiumsupport/knowledge-center/decode-verify-cognito-json-token/
	jwkMap map[string]JWKKey

	// ErrInvalidToken is a general token error
	ErrInvalidToken = errors.New("Invalid Token")
	ErrExpiredToken = errors.New("Token has expired")
	ErrUsageToken   = errors.New("Token usage is wrong: neither id nor access")
	ErrParsingToken = errors.New("Unable to parse token")
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	flag.StringVar(&region, "region", os.Getenv("REGION"), "Region for the AWS Cognito service...")
	flag.StringVar(&clientID, "clientID", os.Getenv("CLIENT_ID"), "Client ID for AWS Cognito")
	flag.StringVar(&clientSecret, "clientSecret", os.Getenv("CLIENT_SECRET"), "Client Secret for AWS Cognito")
	flag.StringVar(&userpoolID, "userpoolID", os.Getenv("USERPOOL_ID"), "UserPool ID for AWS Cognito")
}

// Init initializes all the variables as well as the jwk
func (c *CognitoClient) Init() error {
	flag.Parse()
	idpClient = cogIdp.New(session.New(), &aws.Config{Region: aws.String(region), LogLevel: aws.LogLevel(1)})
	jwkURL = fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v/.well-known/jwks.json", region, userpoolID)
	jwkMap = getJWK(jwkURL)
	log.Println("CognitoClient has been initiated in Init()")

	return nil
}

// SecretHash is for generating secret hash specific to username
func (c *CognitoClient) SecretHash(username string) string {
	log.Info("secret hash ....")
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// SignUp registers a user given the username info
func (c *CognitoClient) SignUp(username, password, confirmPass, email string) (*cogIdp.SignUpOutput, error) {
	// SignUp API: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html
	// TODO: does this user exist already?
	// TODO: validate password and confirm pass, email...

	userInput := cogIdp.SignUpInput{
		Username:       aws.String(username),
		Password:       aws.String(password),
		SecretHash:     aws.String(c.SecretHash(username)),
		UserAttributes: []*cogIdp.AttributeType{generateAttr("email", email)},
		ClientId:       aws.String(clientID),
	}

	return idpClient.SignUp(&userInput)
}

func (c *CognitoClient) SignIn(username, password string) (*cogIdp.InitiateAuthOutput, error) {

	userInput := cogIdp.InitiateAuthInput{
		AnalyticsMetadata: &cogIdp.AnalyticsMetadataType{
			AnalyticsEndpointId: aws.String("no value"), // TODO if necessary
		},
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(username),
			"PASSWORD":    aws.String(password),
			"SECRET_HASH": aws.String(c.SecretHash(username)),
		},
		ClientMetadata: map[string]*string{}, // for validation with pre-set lambda
		ClientId:       aws.String(clientID),
		UserContextData: &cogIdp.UserContextDataType{
			EncodedData: aws.String("encoded string here"),
		},
	}

	return idpClient.InitiateAuth(&userInput)
}

/**
output:
{"level":"info","msg":"output from getting user: %v\n{\n  Enabled: true,\n  UserAttributes: [{\n      Name: \"sub\",\n      Value: \"b6e60099-4efa-4b37-a799-d82e314a71e9\"\n    },{\n      Name: \"email_verified\",\n      Value: \"false\"\n    },{\n      Name: \"email\",\n      Value: \"gwang81@gmail.com\"\n    }],\n  UserCreateDate: 2018-02-20 05:46:17 +0000 UTC,\n  UserLastModifiedDate: 2018-02-20 05:46:17 +0000 UTC,\n  UserStatus: \"UNCONFIRMED\",\n  Username: \"gwang81\"\n}","time":"2018-02-19T22:10:48-08:00"}
*/
func (c *CognitoClient) GetUser(username string) (*cogIdp.AdminGetUserOutput, error) {

	userInput := cogIdp.AdminGetUserInput{
		UserPoolId: aws.String(userpoolID),
		Username:   aws.String(username),
	}

	return idpClient.AdminGetUser(&userInput)
}

func (c *CognitoClient) ConfirmSignUp(code, username string) (*cogIdp.ConfirmSignUpOutput, error) {
	userInput := cogIdp.ConfirmSignUpInput{
		AnalyticsMetadata: &cogIdp.AnalyticsMetadataType{
			AnalyticsEndpointId: aws.String("confirm signup"), // TODO:
		},
		ClientId:           aws.String(clientID),
		ConfirmationCode:   aws.String(code),
		ForceAliasCreation: aws.Bool(false), // see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmSignUp.html#CognitoUserPools-ConfirmSignUp-request-ForceAliasCreation
		SecretHash:         aws.String(c.SecretHash(username)),
		Username:           aws.String(username),
	}
	log.Infof("confirming sing up for code %s and username: %s", code, username)

	return idpClient.ConfirmSignUp(&userInput)
}

// ValidateToken validates the token provided by client
func (c *CognitoClient) ValidateToken(tokenStr string) error {
	token, err := extractToken(tokenStr, region, userpoolID, jwkMap)

	if err != nil {
		return err
	} else if !token.Valid {
		return ErrInvalidToken
	}

	return nil // valid token, no error
}

// ForgotPassword TODO: how to include username in the url/reset password sent by Cognito?
func (c *CognitoClient) ForgotPassword(username string) (*cogIdp.ForgotPasswordOutput, error) {
	userInput := &cogIdp.ForgotPasswordInput{
		AnalyticsMetadata: &cogIdp.AnalyticsMetadataType{
			AnalyticsEndpointId: aws.String("forgot password"), // TODO:
		},
		ClientId:   aws.String(clientID),
		SecretHash: aws.String(c.SecretHash(username)),
		UserContextData: &cogIdp.UserContextDataType{
			EncodedData: aws.String("encoded info here"),
		},
		Username: aws.String(username),
	}
	log.Infof("ForgotPassword request sent to Cognito for username: %s\n", username)

	return idpClient.ForgotPassword(userInput)
}

func (c *CognitoClient) ConfirmForgotPassword(newPass, code, username string) (*cogIdp.ConfirmForgotPasswordOutput, error) {
	userInput := &cogIdp.ConfirmForgotPasswordInput{
		AnalyticsMetadata: &cogIdp.AnalyticsMetadataType{
			AnalyticsEndpointId: aws.String("confirm forgot password"), // TODO:
		},
		ClientId:         aws.String(clientID),
		ConfirmationCode: aws.String(code),
		Password:         aws.String(newPass),
		SecretHash:       aws.String(c.SecretHash(username)),
		UserContextData: &cogIdp.UserContextDataType{
			EncodedData: aws.String("encoded info here"),
		},
		Username: aws.String(username),
	}

	return idpClient.ConfirmForgotPassword(userInput)
}

func (c *CognitoClient) ChangePassword(accessToken, prevPass, newPass string) (*cogIdp.ChangePasswordOutput, error) {
	userInput := &cogIdp.ChangePasswordInput{
		AccessToken:      aws.String(accessToken),
		PreviousPassword: aws.String(prevPass),
		ProposedPassword: aws.String(newPass),
	}

	return idpClient.ChangePassword(userInput)
}

/************ helper functions below ************/
func extractToken(tokenStr, regionName, poolID string, jwk map[string]JWKKey) (*jwt.Token, error) {

	// 2. Decode the token string into JWT format.
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {

		// cognito user pool : RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// 5. Get the kid from the JWT token header and retrieve the corresponding JSON Web Key that was stored
		if kid, ok := token.Header["kid"]; ok {
			if kidStr, ok := kid.(string); ok {
				key := jwk[kidStr]
				// 6. Verify the signature of the decoded JWT token.
				rsaPublicKey := convertKey(key.E, key.N)
				return rsaPublicKey, nil
			}
		}

		// rsa public key取得できず
		return "", nil
	})

	if err != nil {
		return token, err
	}

	claims := token.Claims.(jwt.MapClaims)

	iss, ok := claims["iss"]
	if !ok {
		return token, fmt.Errorf("token does not contain issuer")
	}
	issStr := iss.(string)
	if strings.Contains(issStr, "cognito-idp") {
		// 3. 4. 7.のチェックをまとめて
		err = validateAWSJwtClaims(claims, regionName, poolID)
		if err != nil {
			return token, err
		}
	}

	if token.Valid {
		return token, nil
	}
	return token, err
}

// generateAttr is a helper function that generates an attributeType struct given field and its value
func generateAttr(field, value string) *cogIdp.AttributeType {
	return &cogIdp.AttributeType{
		Name:  aws.String(field),
		Value: aws.String(value),
	}
}

// getJSON is a helper function for downloading json string from the given url, which is decoded to the target interface
// NOTE: code copied from: https://github.com/mura123yasu/go-cognito/blob/master/verifyToken.go
func getJSON(url string, target interface{}) error {
	var myClient = &http.Client{Timeout: 10 * time.Second}
	r, err := myClient.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(target)
}

func getJWK(jwkURL string) map[string]JWKKey {

	jwk := &JWK{}

	getJSON(jwkURL, jwk)

	jwkMap := make(map[string]JWKKey, 0)
	for _, entryValue := range jwk.Keys {
		jwkMap[entryValue.Kid] = entryValue
	}
	return jwkMap
}

// validateAWSJwtClaims validates AWS Cognito User Pool JWT
func validateAWSJwtClaims(claims jwt.MapClaims, regionName, poolID string) error {
	var err error
	// 3. Check the iss claim. It should match your user pool.
	issShoudBe := fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v", regionName, poolID)
	err = validateClaimItem("iss", []string{issShoudBe}, claims)
	if err != nil {
		return err
	}

	// 4. Check the token_use claim.
	validateTokenUse := func() error {
		if tokenUse, ok := claims["token_use"]; ok {
			if tokenUseStr, ok := tokenUse.(string); ok {
				if tokenUseStr == "id" || tokenUseStr == "access" {
					return nil
				}
			}
		}
		return ErrUsageToken
	}

	err = validateTokenUse()
	if err != nil {
		return err
	}

	// 7. Check the exp claim and make sure the token is not expired.
	err = validateExpired(claims)
	if err != nil {
		return err
	}

	return nil
}

func validateClaimItem(key string, keyShouldBe []string, claims jwt.MapClaims) error {
	if val, ok := claims[key]; ok {
		if valStr, ok := val.(string); ok {
			for _, shouldbe := range keyShouldBe {
				if valStr == shouldbe {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%v does not match any of valid values: %v", key, keyShouldBe)
}

func validateExpired(claims jwt.MapClaims) error {
	if tokenExp, ok := claims["exp"]; ok {
		if exp, ok := tokenExp.(float64); ok {
			now := time.Now().Unix()
			log.Infof("current unixtime : %v\n", now)
			log.Infof("expire unixtime  : %v\n", int64(exp))
			if int64(exp) > now {
				return nil
			}
		}
		return ErrParsingToken
	}
	return ErrExpiredToken
}

// source: https://gist.github.com/MathieuMailhos/361f24316d2de29e8d41e808e0071b13
func convertKey(rawE, rawN string) *rsa.PublicKey {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		panic(err)
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey
}
