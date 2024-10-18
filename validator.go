package validation

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
	"github.com/gofiber/fiber/v2"
	ut "github.com/templatedop/universal-translator-master"
)

type (
	FieldError struct {
		FailedField string `json:"field"`
		Tag         string `json:"tag"`
		//Param string `json:"param"`
		Value   interface{} `json:"value"`
		Message string      `json:"message"`
	}

	Error struct {
		msg  string
		errs []FieldError
	}
)

// Need to check translator and add additional functionality

var (
	validate           *validator.Validate
	uni                *ut.UniversalTranslator
	trans              ut.Translator
	validationMessages = map[string]func(string, any) string{}
)

var structFieldTags = []string{"json", "param", "query"}

func getStructFieldName(fld reflect.StructField) string {
	for _, st := range structFieldTags {
		name := strings.SplitN(fld.Tag.Get(st), ",", 2)[0]

		if name == "" {
			continue
		}

		if name == "-" {
			return ""
		}

		return name
	}

	return fld.Name
}

// func Init(rules []Rule) {

// 	validate = validator.New()
// 	eng := en.New()
// 	uni = ut.New(eng, eng)
// 	trans, _ = uni.GetTranslator("en")

// 	// Register default translations for the validator
// 	if err := en_translations.RegisterDefaultTranslations(validate, trans); err != nil {
// 		panic(fmt.Sprintf("Failed to register translations: %v", err))
// 		//log.Fatalf("Failed to register translations: %v", err)
// 	}
// 	validate.RegisterTagNameFunc(getStructFieldName)

// 	for _, r := range rules {
// 		if err := validate.RegisterValidation(r.Name(), r.Apply); err != nil {
// 			panic(err.Error())
// 		}
// 		validationMessages[r.Name()] = r.Message
// 	}
// }

type val struct {
	*validator.Validate
}

func NewValidator(v *validator.Validate) *val {
	return &val{v}
}

func Create(rules []Rule) (func() *val, error) {
	validate := validator.New()
	eng := en.New()
	uni := ut.New(eng, eng)
	trans, _ := uni.GetTranslator("en")

	// Register default translations for the validator
	if err := en_translations.RegisterDefaultTranslations(validate, trans); err != nil {
		return nil, fmt.Errorf("failed to register translations: %v", err)
	}

	validate.RegisterTagNameFunc(getStructFieldName)

	for _, r := range rules {
		if err := validate.RegisterValidation(r.Name(), r.Apply); err != nil {
			return nil, err
		}
		validationMessages[r.Name()] = r.Message
	}

	return func() *val {
		return NewValidator(validate)
	}, nil
}

func ValidateStruct(s interface{}) error {

	if validate == nil {
		panic("validator not initialized")
	}

	if trans == nil {
		panic("translator not initialized")
	}
	//var fieldErrors validation.FieldErrors
	err := validate.Struct(s)
	if err != nil {
		var fieldErrors []FieldError
		var validatorErrors validator.ValidationErrors

		errors.As(err, &validatorErrors)

		for _, e := range validatorErrors {

			tag := e.Tag()
			if _, ok := validationMessages[tag]; ok {
				fieldErrors = append(fieldErrors, FieldError{
					FailedField: e.Field(),

					Tag:     e.Param(),
					Value:   e.Value(),
					Message: getTagMessage(e),
				})

			} else {
				fieldErrors = append(fieldErrors, FieldError{
					FailedField: e.Field(),
					Tag:         e.Tag(),
					Value:       e.Value(),
					Message:     e.Translate(trans),
				})

			}

		}

		return &Error{
			msg:  "validation error",
			errs: fieldErrors,
		}

	}
	return nil
}

func (ve *Error) Unwrap() error {
	return fiber.ErrBadRequest
}

func (ve *Error) Error() string {
	return ve.msg
}

func (ve *Error) FieldErrors() []FieldError {
	return ve.errs
}

func (fe FieldError) Error() string {
	return fe.Message
}

func getTagMessage(err validator.FieldError) string {
	if mr, ok := validationMessages[err.Tag()]; ok {
		return mr(err.Field(), err.Value())
	}

	return err.Error()
}
