package validation

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
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

func getDefaultRules() []Rule {
	return []Rule{
		NewValidateHOAPatternValidator(),
		NewPersonnelNameValidator(),
		NewAddressPatternValidator(),
		NewEmailValidator(),
		NewGValidatePhoneLengthPatternValidator(),
		NewGValidateSOBONamePatternValidator(),
		NewGValidatePANNumberPatternValidator(),
		NewGValidateVehicleRegistrationNumberPatternValidator(),
		NewGValidateBarCodeNumberPatternValidator(),
		NewCustomValidateGLCodePatternValidator(),
		NewTimeStampValidatePatternValidator(),
		NewCustomValidateAnyStringLengthto50PatternValidator(),
		NewDateyyyymmddPatternValidator(),
		NewDateddmmyyyyPatternValidator(),
		NewValidateEmployeeIDPatternValidator(),
		NewValidateValidateGSTINPatternValidator(),
		NewValidateBankUserIDPatternValidator(),
		NewValidateOrderNumberPatternValidator(),
		NewValidateAWBNumberPatternValidator(),
		NewValidatePNRNoPatternValidator(),
		NewValidatePLIIDPatternValidator(),
		NewValidatePaymentTransIDPatternValidator(),
		NewValidateOfficeCustomerIDPatternValidator(),
		NewValidateBankIDPatternValidator(),
		NewValidateCSIFacilityIDPatternValidator(),
		NewValidatePosBookingOrderNumberPatternValidator(),
		NewValidateSOLIDPatternValidator(),
		NewValidatePLIOfficeIDPatternValidator(),
		NewValidateProductCodePatternValidator(),
		NewValidateCustomerIDPatternValidator(),
		NewValidateFacilityIDPatternValidator(),
		NewValidateApplicationIDPatternValidator(),
		NewValidateReceiverKYCReferencePatternValidator(),
		NewValidateOfficeCustomerPatternValidator(),
		NewValidatePRANPatternValidator(),
		NewvalidateCustomFlightNoValidator(),
		NewvalidatePinCodeGlobalValidator(),
		NewValidatePhoneNumberStringPatternValidator(),
		NewCustomofficeidGlobalValidator(),
		NewvalidateBagIdPatternValidator(),
		NewCustomTrainNoGlobalValidator(),
		NewCustomSCSGlobalValidator(),
		NewvalidateCircleIDGlobalValidator(),
		NewvalidateTariffIDGlobalValidator(),
		NewvalidateCIFNumGlobalValidator(),
		NewvalidateContractNumGlobalValidator(),
		NewvalidateRegionIDGlobalValidator(),
		NewvalidateVasIDGlobalValidator(),
		NewvalidateUserCodeGlobalValidator(),
		NewvalidateHONamePatternValidator(),
		NewvalidateHOIDGlobalValidator(),
		NewvalidateAccountNoGlobalValidator(),
		NewIsValidTimestampGlobalValidator(),
	}
}

func registerDefaultRules(rules []Rule, val *validator.Validate) error {
	for _, r := range rules {
		if err := val.RegisterValidation(r.Name(), r.Apply); err != nil {
			return err
		}
		validationMessages[r.Name()] = r.Message
	}
	return nil
}

func Create() (*val, error) {
	rules := getDefaultRules()
	validate = validator.New()
	eng := en.New()
	uni = ut.New(eng, eng)
	trans, _ = uni.GetTranslator("en")

	// Register default translations for the validator
	if err := en_translations.RegisterDefaultTranslations(validate, trans); err != nil {
		return nil, err
		//log.Fatalf("Failed to register translations: %v", err)
	}
	validate.RegisterTagNameFunc(getStructFieldName)
	err := registerDefaultRules(rules, validate)
	if err != nil {
		return nil, err
	}
	return NewValidator(validate), nil
}

func (v *val) ValidateStruct(s interface{}) error {

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
			if Emsg, ok := validationMessages[tag]; ok {
				fieldErrors = append(fieldErrors, FieldError{
					FailedField: e.Field(),

					Tag:     e.Param(),
					Value:   e.Value(),
					Message: Emsg(e.Field(), e.Value()),
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

// func (ve *Error) Unwrap() error {
// 	return fiber.ErrBadRequest
// }

func (ve *Error) Error() string {
	return ve.msg
}

func (v *val) RegisterCustomValidation(tag string, fn validator.Func, message string) error {
	if tag == "" {
		return errors.New("validation tag cannot be empty")
	}
	if fn == nil {
		return errors.New("validation function cannot be nil")
	}

	if _, exists := validationMessages[tag]; exists {
		return fmt.Errorf("validation tag '%s' is already registered", tag)
	}

	rule := NewRule(tag, fn, message)
	err := registerDefaultRules([]Rule{rule}, validate)
	if err != nil {
		return err
	}

	return nil
}

// func (ve *Error) FieldErrors() []FieldError {
// 	return ve.errs
// }

// func (fe FieldError) Error() string {
// 	return fe.Message
// }

// func getTagMessage(err validator.FieldError) string {
// 	if mr, ok := validationMessages[err.Tag()]; ok {
// 		return mr(err.Field(), err.Value())
// 	}

// 	return err.Error()
// }
