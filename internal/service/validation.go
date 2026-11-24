package service

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateName(name string) error {
	length := utf8.RuneCountInString(name)
	switch {
	case length <= 3:
		return &ValidationError{Field: "name", Message: "must be longer than 3 characters"}
	case length > 120:
		return &ValidationError{Field: "name", Message: "must be at most 120 characters"}
	}
	return nil
}

func validateEmail(email string) error {
	if email == "" {
		return &ValidationError{Field: "email", Message: "is required"}
	}
	if len(email) > 180 {
		return &ValidationError{Field: "email", Message: "must be at most 180 characters"}
	}

	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return &ValidationError{Field: "email", Message: "must be a valid email"}
	}

	at := strings.LastIndex(email, "@")
	domain := email[at+1:]
	if domain == "org" || strings.HasSuffix(domain, ".org") {
		return &ValidationError{Field: "email", Message: "domain .org is not allowed"}
	}
	if domain == "edu.br" || strings.HasSuffix(domain, ".edu.br") {
		return &ValidationError{Field: "email", Message: "domain .edu.br is not allowed"}
	}
	return nil
}

func validatePassword(field, password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return &ValidationError{Field: field, Message: "must be at least 8 characters"}
	}
	// bcrypt only considers the first 72 bytes.
	if len(password) > 72 {
		return &ValidationError{Field: field, Message: "must be at most 72 bytes"}
	}

	var hasLetter, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		case !unicode.IsSpace(r):
			hasSpecial = true
		}
	}

	switch {
	case !hasLetter:
		return &ValidationError{Field: field, Message: "must contain at least one letter"}
	case !hasDigit:
		return &ValidationError{Field: field, Message: "must contain at least one number"}
	case !hasSpecial:
		return &ValidationError{Field: field, Message: "must contain at least one special character"}
	}
	return nil
}

func validateRecoveryCode(code string) error {
	if len(code) != 6 {
		return &ValidationError{Field: "code", Message: "must contain exactly 6 digits"}
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return &ValidationError{Field: "code", Message: "must contain exactly 6 digits"}
		}
	}
	return nil
}
