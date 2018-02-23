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
			"Username": aws.String(username),
			"Password": aws.String(password),
		},
		ClientMetadata: map[string]*string{}, // for validation with pre-set lambda
		ClientId:       aws.String(clientID),
		UserContextData: &cogIdp.UserContextDataType{
			EncodedData: aws.String("ip:192.168.1.169"),
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
			AnalyticsEndpointId: aws.String("no value"), // TODO:
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

// verify token: https://aws.amazon.com/premiumsupport/knowledge-center/decode-verify-cognito-json-token/
// example: https://github.com/mura123yasu/go-cognito/blob/master/verifyToken.go and https://gist.github.com/MathieuMailhos/361f24316d2de29e8d41e808e0071b13

// generateAttr is a helper function that generates an attributeType struct given field and its value
func generateAttr(field, value string) *cogIdp.AttributeType {
	return &cogIdp.AttributeType{
		Name:  aws.String(field),
		Value: aws.String(value),
	}
}
