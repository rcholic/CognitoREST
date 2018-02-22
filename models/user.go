package models

// see references: https://github.com/netlify/gotrue, https://github.com/qor/qor-example/, https://github.com/micro/user-srv/blob/master/handler/handler.go
// qor doc: https://doc.getqor.com/guides/authentication.html

/**
Amazon Cognito:
Pool Id us-east-1_WNzBU8Quv
Pool ARN arn:aws:cognito-idp:us-east-1:014997285570:userpool/us-east-1_WNzBU8Quv
*/

// NameValuePair is a generic structure for UserAttributes and ValidationData
type NameValuePair struct {
	Name  string
	Value string
}

// User represents user object
type User struct {
	// gorm.Model
	Username       string //`json:"username"`
	Email          string //`json:"email"`
	Password       string //`json:"password"`
	Phone          string //`json:"phone"`
	UserAttributes []NameValuePair
}

// Sanitize removes sensitive field value
func (u *User) Sanitize() {
	u.Password = "****"
}
