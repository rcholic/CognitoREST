package models

import (
	cogIdp "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// see references: https://github.com/netlify/gotrue, https://github.com/qor/qor-example/, https://github.com/micro/user-srv/blob/master/handler/handler.go
// qor doc: https://doc.getqor.com/guides/authentication.html

/**
Amazon Cognito:
Pool Id us-east-1_WNzBU8Quv
Pool ARN arn:aws:cognito-idp:us-east-1:014997285570:userpool/us-east-1_WNzBU8Quv
*/

// User represents user object
type User struct {
	// gorm.Model
	Username       string //`json:"username"`
	Email          string //`json:"email"`
	Password       string //`json:"password"`
	Phone          string //`json:"phone"`
	UserAttributes []*cogIdp.AttributeType
}

// Sanitize removes sensitive field value
func (u *User) Sanitize() {
	u.Password = "****"
}

/* SignUp: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SignUp.html#CognitoUserPools-SignUp-request-AnalyticsMetadata */
