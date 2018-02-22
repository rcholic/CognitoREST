package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	// "log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cogIdp "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/rcholic/rally_bargain/user/models"
	log "github.com/sirupsen/logrus"
)

// AWSCognito methods interface
type AWSCognito interface {
	Init() error
	SecretHash(string) string
	SignUp(string, string, string, string) (models.User, error)
	SignIn(string, string) (models.User, error)
	GetUser(string) (models.User, error)
	ConfirmSignUp(string) (models.User, bool)
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

func (c *CognitoClient) Init() error {
	flag.Parse()
	idpClient = cogIdp.New(session.New(), &aws.Config{Region: aws.String(region), LogLevel: aws.LogLevel(1)})
	log.Printf("CognitoClient has been initiated in Init(), region: %s\n", region)
	return nil
}

func (c *CognitoClient) SecretHash(username string) string {
	log.Info("secret hash ....")
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// SignUp registers a user given the username info
func (c *CognitoClient) SignUp(username, password, confirmPass, email string) (models.User, error) {
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

	res, err := idpClient.SignUp(&userInput)
	if err != nil {
		log.Fatalf("err in cognito client sign up %v\n", err)
	}
	log.Info("sign up success, res: %v\n", res)
	/**
	output:
	{"level":"info","msg":"sign up success, res: %v\n{\n  CodeDeliveryDetails: {\n    AttributeName: \"email\",\n    DeliveryMedium: \"EMAIL\",\n    Destination: \"g***@g***.com\"\n  },\n  UserConfirmed: false,\n  UserSub: \"b6e60099-4efa-4b37-a799-d82e314a71e9\"\n}","time":"2018-02-19T21:46:18-08:00"}

	*/

	return models.User{}, nil
}

func (c *CognitoClient) SignIn(username, password string) (models.User, error) {
	return models.User{}, nil
}

/**
output:

{"level":"info","msg":"output from getting user: %v\n{\n  Enabled: true,\n  UserAttributes: [{\n      Name: \"sub\",\n      Value: \"b6e60099-4efa-4b37-a799-d82e314a71e9\"\n    },{\n      Name: \"email_verified\",\n      Value: \"false\"\n    },{\n      Name: \"email\",\n      Value: \"gwang81@gmail.com\"\n    }],\n  UserCreateDate: 2018-02-20 05:46:17 +0000 UTC,\n  UserLastModifiedDate: 2018-02-20 05:46:17 +0000 UTC,\n  UserStatus: \"UNCONFIRMED\",\n  Username: \"gwang81\"\n}","time":"2018-02-19T22:10:48-08:00"}
*/
func (c *CognitoClient) GetUser(username string) (models.User, error) {

	userInput := cogIdp.AdminGetUserInput{
		UserPoolId: aws.String(userpoolID),
		Username:   aws.String(username),
	}

	output, err := idpClient.AdminGetUser(&userInput)
	if err != nil {
		log.Fatalf("err in getting user: %v\n", err)
	}
	log.Info("output from getting user: %v\n", output)

	return models.User{}, nil
}

func (c *CognitoClient) ConfirmSignUp(code string) (models.User, bool) {
	return models.User{}, true
}

// verify token: https://aws.amazon.com/premiumsupport/knowledge-center/decode-verify-cognito-json-token/
// example: https://github.com/mura123yasu/go-cognito/blob/master/verifyToken.go and https://gist.github.com/MathieuMailhos/361f24316d2de29e8d41e808e0071b13

// generateAttr is a helper function that generates an attributeType struct given field and its value
func generateAttr(field, value string) *cogIdp.AttributeType {
	return &cogIdp.AttributeType{
		Name:  aws.String(field),
		Value: aws.String(value),
	}
}
