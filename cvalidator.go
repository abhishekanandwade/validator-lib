package validation

import (
	"regexp"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
)

var (
	HOAPattern                               = regexp.MustCompile(`^\d{15}$`)
	PersonnelNamePattern                     = regexp.MustCompile(`^[A-Za-z][A-Za-z\s]{1,48}[A-Za-z]$`)
	AddressPattern                           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9\s,.-]{1,48}[A-Za-z0-9]$`)
	EmailPattern                             = regexp.MustCompile(`^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	PhoneLengthPattern                       = regexp.MustCompile(`^\d{10}$`)
	SOBONamePattern                          = regexp.MustCompile(`^[A-Za-z][A-Za-z\s]{1,48}[A-Za-z]$`)
	PANNumberPattern                         = regexp.MustCompile(`^[A-Z]{5}[0-9]{4}[A-Z]$`)
	VehicleRegistrationNumberPattern         = regexp.MustCompile(`^[A-Z]{2}\d{2}[A-Z]{1,2}\d{4,7}$ |\d{2}[A-Z]{2}\d{4}[A-Z]{2}$`)
	BarCodeNumberPattern                     = regexp.MustCompile(`^[A-Z]{2}\d{6,12}[A-Z]{2}$`)
	GLCodePattern                            = regexp.MustCompile(`^GL\d{11}$`)
	timeStampPattern                         = regexp.MustCompile(`^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-(\d{4}) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$`)
	customValidateAnyStringLengthto50Pattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,48}[a-zA-Z]$`)
	dateyyyymmddPattern                      = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`)
	dateddmmyyyyPattern                      = regexp.MustCompile(`^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-\d{4}$`)
	EmployeeIDPattern                        = regexp.MustCompile(`^\d{8}$`)
	GSTINPattern                             = regexp.MustCompile(`^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[A-Z0-9]{1}[Z]{1}[0-9]{1}$`)
	specialCharPattern                       = regexp.MustCompile(`[!@#$%^&*()<>:;"{}[\]\\]`)
	BankUserIDPattern                        = regexp.MustCompile(`^[A-Z0-9]{1,50}$`)
	OrderNumberPattern                       = regexp.MustCompile(`^[A-Z]{2}\d{19}$`)
	AWBNumberPattern                         = regexp.MustCompile(`^[A-Z]{4}\d{9}$`)
	PNRNoPattern                             = regexp.MustCompile(`^[A-Z]{3}\d{6}$`)
	PLIIDPattern                             = regexp.MustCompile(`^[A-Z]{3}\d{10}$`)
	PaymentTransIDPattern                    = regexp.MustCompile(`^\d{2}[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
	OfficeCustomerIDPattern                  = regexp.MustCompile(`^[a-zA-Z0-9\-]{1,50}$`)
	BankIDPattern                            = regexp.MustCompile(`^[A-Z0-9]{1,50}$`)
	CSIFacilityIDPattern                     = regexp.MustCompile(`^[A-Z]{2}\d{11}$`)
	PosBookingOrderNumberPattern             = regexp.MustCompile(`^[A-Z]{2}\d{19}$`)
	SOLIDPattern                             = regexp.MustCompile(`^\d{6}\d{2}$`)
	PLIOfficeIDPattern                       = regexp.MustCompile(`^[A-Z]{3}\d{10}$`)
	ProductCodePattern                       = regexp.MustCompile(`^[A-Z]{3}\d{12}$`)
	CustomerIDPattern                        = regexp.MustCompile(`^\d{10}$`)
	FacilityIDPattern                        = regexp.MustCompile(`^[A-Z]{2}\d{11}$`)
	ApplicationIDPattern                     = regexp.MustCompile(`^[A-Z]{3}\d{8}-\d{3}$`)
	ReceiverKYCReferencePattern              = regexp.MustCompile(`^KYCREF[A-Z0-9]{0,44}$`)
	OfficeCustomerPattern                    = regexp.MustCompile(`^[a-zA-Z0-9\s]+$`)
	PRANPattern                              = regexp.MustCompile(`^\d{12}$`)
	FlightNopattern                          = regexp.MustCompile("^[A-Za-z0-9 ]+$")
	allZerosRegex                            = regexp.MustCompile("^0+$")
	PhoneNumberStringPattern                 = regexp.MustCompile(`^[6-9]\d{9}$`)
	bagIdPattern                             = regexp.MustCompile(`^(?:[A-Za-z]{3}\d{10}|[A-Za-z]{15}\d{14})$`)
	trainNoPattern                           = regexp.MustCompile(`^\d{5}$`)
)

func NewValidateHOAPatternValidator() Rule {
	return NewRule("head_of_account", validateHOAPattern, "the %s must be 15 digits")
}
func NewPersonnelNameValidator() Rule {
	return NewRule("personnel_name", validatePersonnelNamePattern, "the %s  must start and end with a letter(capital and small letters allowed) and can contain spaces in between. It should be between 3 and 50 characters long, where the middle part can include letters and spaces.")
}
func NewAddressPatternValidator() Rule {
	return NewRule("address", validateAddressPattern, "the %s must start and end with an alphanumeric character, and may contain letters, digits, spaces, commas, periods, and hyphens in between. The total length should be between 3 and 50 characters. ")
}

func NewEmailValidator() Rule {
	return NewRule("simple_email", validateEmailPattern, "the %s must follow the format: local-part@domain.tld, where the local part can include letters, digits, and special characters (._+-), and the domain must contain at least one dot followed by a top-level domain of at least 2 letters")
}
func NewGValidatePhoneLengthPatternValidator() Rule {
	return NewRule("phone_length", validatePhoneLengthPattern, "the %s must be 10 digits long and should be between (1000000000 9999999999)")
}
func NewGValidateSOBONamePatternValidator() Rule {
	return NewRule("so_bo_name", validateSOBONamePattern, "the %s  must start and end with a letter, contain only letters and spaces, and be between 3 and 50 characters long")
}
func NewGValidatePANNumberPatternValidator() Rule {
	return NewRule("pan_number", validatePANNumberPattern, "the %s must consist of exactly 5 uppercase letters, followed by 4 digits, and ending with 1 uppercase letter")
}
func NewGValidateVehicleRegistrationNumberPatternValidator() Rule {
	return NewRule("vehicle_registration_number", validateVehicleRegistrationNumberPattern, "the %s must either be in the format 'XX99XX9999' or '99XX9999XX' where 'XX' is a letter and '99' is a digit")
}
func NewGValidateBarCodeNumberPatternValidator() Rule {
	return NewRule("bar_code_number", validateBarCodeNumberPattern, "the %s  must consist of 2 uppercase letters, followed by 6 to 12 digits, and ending with 2 uppercase letters ")
}
func NewCustomValidateGLCodePatternValidator() Rule {
	return NewRule("gl_code", customValidateGLCodePattern, "the %s must start with 'GL' followed by exactly 11 digits")
}
func NewTimeStampValidatePatternValidator() Rule {
	return NewRule("date_time_stamp", timeStampValidatePattern, "the %s must be in the format 'DD-MM-YYYY HH:MM:SS', with a valid day (01-31), month (01-12), and time in 24-hour format (00-23:00-59:00-59)")
}
func NewCustomValidateAnyStringLengthto50PatternValidator() Rule {
	return NewRule("customValidateAnyStringLengthto50Pattern", validateAnyStringLengthto50Pattern, "the %s must start and end with a letter and can contain up to 50 characters total, including letters and numbers")
}
func NewDateyyyymmddPatternValidator() Rule {
	return NewRule("date_yyyy_mm_dd", validatedateyyyymmddPattern, "the %s must be in the format 'YYYY-MM-DD', where YYYY is the year, MM is the month (01-12), and DD is the day (01-31)")
}

func NewDateddmmyyyyPatternValidator() Rule {
	return NewRule("date_dd_mm_yyyy", validatedateddmmyyyyPattern, "the %s must be in the format 'DD-MM-YYYY', where DD is the day (01-31), MM is the month (01-12), and YYYY is the year (4 digits)")
}

func NewValidateEmployeeIDPatternValidator() Rule {
	return NewRule("employee_id", validateEmployeeIDPattern, "the %s must be exactly 8 digits ")
}
func NewValidateValidateGSTINPatternValidator() Rule {
	return NewRule("gst_in", validateGSTINPattern, "the %s must be in the format 'XXYYYYYZZZZZ0', where XX is the state code (2 digits), YYYYY is the business name (5 letters), ZZZZ is the registration number (4 digits), A is the entity type (1 letter), B is an alphanumeric character (1), Z is a fixed character, and C is a checksum digit (1 digit)")
}

// ********************************

func NewValidateBankUserIDPatternValidator() Rule {
	return NewRule("bank_user_id", validateBankUserIDPattern, "the %s must contain between 1 and 50 characters, consisting of uppercase letters and digits only")
}
func NewValidateOrderNumberPatternValidator() Rule {
	return NewRule("order_number", ValidateOrderNumberPattern, "the %s must be in the format 'LLDDDDDDDDDDDDDDDDDD', where 'LL' are 2 uppercase letters and 'DDDDDDDDDDDDDDDDDDD' are 19 digits")
}

func NewValidateAWBNumberPatternValidator() Rule {
	return NewRule("awb_number", validateAWBNumberPattern, "the %s must be in the format 'LLLLDDDDDDDDD', where 'LLLL' are 4 uppercase letters and 'DDDDDDDDD' are 9 digits")
}

func NewValidatePNRNoPatternValidator() Rule {
	return NewRule("pnr_no", validatePNRNoPattern, "the %s must be in the format 'LLLDDDDDD', where 'LLL' are 3 uppercase letters and 'DDDDDD' are 6 digits")
}
func NewValidatePLIIDPatternValidator() Rule {
	return NewRule("pli_id", validatePLIIDPattern, "the %s must be in the format 'LLLDDDDDDDD', where 'LLL' are 3 uppercase letters and 'DDDDDDDDDD' are 10 digits")
}
func NewValidatePaymentTransIDPatternValidator() Rule {
	return NewRule("payment_trans_id", validatePaymentTransIDPattern, "the %s  must be in the format 'XXYYYYYYYY-YYYY-4YYY-ZZZZ-YYYYYYYYYYYY', where 'XX' are 2 digits, 'Y' are hexadecimal characters, and 'Z' are hexadecimal characters with specific rules for version and variant")
}
func NewValidateOfficeCustomerIDPatternValidator() Rule {
	return NewRule("office_customer_id", validateOfficeCustomerIDPattern, "the %s must contain between 1 and 50 characters, consisting of letters, digits, and hyphens only")
}
func NewValidateBankIDPatternValidator() Rule {
	return NewRule("bank_id", validateBankIDPattern, "the %s must contain between 1 and 50 characters, consisting of uppercase letters and digits only")
}
func NewValidateCSIFacilityIDPatternValidator() Rule {
	return NewRule("csi_facility_id", validateCSIFacilityIDPattern, "the %s must be in the format 'LLDDDDDDDDDDD', where 'LL' are 2 uppercase letters and 'DDDDDDDDDDDDD' are 11 digits")
}
func NewValidatePosBookingOrderNumberPatternValidator() Rule {
	return NewRule("pos_booking_order_number", validatePosBookingOrderNumberPattern, "the %s must be in the format 'LLDDDDDDDDDDDDDDDDD', where 'LL' are 2 uppercase letters and 'DDDDDDDDDDDDDDDDDDD' are 19 digits ")
}
func NewValidateSOLIDPatternValidator() Rule {
	return NewRule("sol_id", validateSOLIDPattern, "the %s must be exactly 8 digits")
}
func NewValidatePLIOfficeIDPatternValidator() Rule {
	return NewRule("pli_office_id", validatePLIOfficeIDPattern, "the %s must be in the format 'LLLDDDDDDDD', where 'LLL' are 3 uppercase letters and 'DDDDDDDDDD' are 10 digits")
}
func NewValidateProductCodePatternValidator() Rule {
	return NewRule("product_code", validateProductCodePattern, "the %s must be in the format 'LLLDDDDDDDDDD', where 'LLL' are 3 uppercase letters and 'DDDDDDDDDDDD' are 12 digits")
}
func NewValidateCustomerIDPatternValidator() Rule {
	return NewRule("customer_id", validateCustomerIDPattern, "the %s must be exactly 10 digits")
}
func NewValidateFacilityIDPatternValidator() Rule {
	return NewRule("facility_id", validateFacilityIDPattern, "the %s must be in the format 'LLDDDDDDDDDDD', where 'LL' are 2 uppercase letters and 'DDDDDDDDDDD' are 11 digits")
}
func NewValidateApplicationIDPatternValidator() Rule {
	return NewRule("application_id", validateApplicationIDPattern, "the %s must be in the format 'LLLDDDDDDDD-DDD', where 'LLL' are 3 uppercase letters, 'DDDDDDDD' are 8 digits, and 'DDD' are 3 digits after the hyphen")
}
func NewValidateReceiverKYCReferencePatternValidator() Rule {
	return NewRule("receiver_kyc_reference", validateReceiverKYCReferencePattern, "the %s must start with 'KYCREF' followed by up to 44 alphanumeric characters")
}
func NewValidateOfficeCustomerPatternValidator() Rule {
	return NewRule("office_customer", validateOfficeCustomerPattern, "the %s must consist of letters, numbers, and spaces only, and cannot be empty(special characters are not allowed)")
}
func NewValidatePRANPatternValidator() Rule {
	return NewRule("pran_no", validatePRANPattern, "the %s must be exactly 12 digits")
}

func NewvalidateCustomFlightNoValidator() Rule {
	return NewRule("flight_no", validateCustomFlightNo, "the %s must contain only letters, digits, and spaces")
}
func NewvalidatePinCodeGlobalValidator() Rule {
	return NewRule("custom_pincode", validatePinCodeGlobal, "the %s must be 6 digits. The first digit must be 1-9, last five digits cant be all zeros and also last three digits cant be all zeros")
}
func NewValidatePhoneNumberStringPatternValidator() Rule {
	return NewRule("phone_number", ValidatePhoneNumberStringPattern, "the %s must be a valid 10-digit phone number starting with a digit between 6 and 9")
}
func NewCustomofficeidGlobalValidator() Rule {
	return NewRule("office_id", customofficeidGlobal, "the %s must be between 1000000 & 99999999")
}
func NewvalidateBagIdPatternValidator() Rule {
	return NewRule("bag_id", validateBagIdPattern, "the %s must be a valid bag ID with either 3 letters followed by 10 digits(domestic), or 15 letters followed by 14 digits(international)")
}
func NewCustomTrainNoGlobalValidator() Rule {
	return NewRule("train_no", customTrainNoGlobal, "the %s must be a valid bag ID with either 3 letters followed by 10 digits(domestic), or 15 letters followed by 14 digits(international)")
}
func NewCustomSCSGlobalValidator() Rule {
	return NewRule("seating_capacity", customSCSGlobal, "the %s must be a number between 1 and 9999")
}
func NewvalidateCircleIDGlobalValidator() Rule {
	return NewRule("circle_id", validateCircleIDGlobal, "the %s must be a number between 1 and 9999")
}
func NewvalidateTariffIDGlobalValidator() Rule {
	return NewRule("tariff_id", validateTariffIDGlobal, "the %s must be a number between 1000000000 & 9999999999")
}
func NewvalidateCIFNumGlobalValidator() Rule {
	return NewRule("cif_number", validateCIFNumGlobal, "the %s must be a number between 100000000 & 999999999")
}
func NewvalidateContractNumGlobalValidator() Rule {
	return NewRule("contract_number", validateContractNumGlobal, "the %s must be a number between 10000000 & 99999999")
}

func NewvalidateRegionIDGlobalValidator() Rule {
	return NewRule("region_id", validateRegionIDGlobal, "the %s must be a number between 1000000 & 9999999")
}
func NewvalidateVasIDGlobalValidator() Rule {
	return NewRule("vas_id", validateVasIDGlobal, "the %s must be a number between 1000000 & 9999999")
}

func NewvalidateUserCodeGlobalValidator() Rule {
	return NewRule("user_code", validateUserCodeGlobal, "the %s must be a number between 10000000 & 99999999")
}

func NewvalidateHONamePatternValidator() Rule {
	return NewRule("ho_id", validateHONamePattern, "the %s must not contain any special characters  ")
}
func NewvalidateHOIDGlobalValidator() Rule {
	return NewRule("ho_name", validateHOIDGlobal, "the %s must be a number between 1000000 &  9999999 ")
}
func NewvalidateAccountNoGlobalValidator() Rule {
	return NewRule("account_no", validateAccountNoGlobal, "the %s must be a number between 1000000000 & 9999999999 ")
}

func NewIsValidTimestampGlobalValidator() Rule {
	return NewRule("time_stamp", isValidTimestampGlobal, "the %s must be a number between 1000000000 & 9999999999 ")
}

// validate time stamp in format:2024-01-01T00:00:00Z
func isValidTimestampGlobal(fl validator.FieldLevel) bool {
	// Parse the field as a time.Time
	_, err := time.Parse(time.RFC3339, fl.Field().String())
	return err != nil
}

// ///////////////////////////////////////////
func ValidateWithGlobalRegex(fl validator.FieldLevel, regex *regexp.Regexp) bool {
	fieldValue := fl.Field().String()
	return regex.MatchString(fieldValue)
}

// ////////////////////////////////////////////////////////////
func validateHOAPattern(fl validator.FieldLevel) bool {
	//pattern := `^\d{15}$`
	return ValidateWithGlobalRegex(fl, HOAPattern)
}
func validatePersonnelNamePattern(fl validator.FieldLevel) bool {
	return ValidateWithGlobalRegex(fl, PersonnelNamePattern)
}
func validateAddressPattern(fl validator.FieldLevel) bool {
	return ValidateWithGlobalRegex(fl, AddressPattern)
}
func validateEmailPattern(fl validator.FieldLevel) bool {
	return ValidateWithGlobalRegex(fl, EmailPattern)
}
func validatePhoneLengthPattern(fl validator.FieldLevel) bool {
	// Handle the case where the phone number is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Validate using a regular expression for exactly 10 digits
		// pattern := `^\d{10}$`
		// return ValidateWithRegex(fl, pattern)
		return ValidateWithGlobalRegex(fl, PhoneLengthPattern)
	}

	// Handle the case where the phone number is a uint64
	if phoneNumber, ok := fl.Field().Interface().(uint64); ok {
		// Check if the phone number has exactly 10 digits
		return phoneNumber >= 1000000000 && phoneNumber <= 9999999999
	}
	//works only for 64 bit system
	// Handle the case where the phone number is an int
	if phoneNumber, ok := fl.Field().Interface().(int); ok {
		// Check if the phone number has exactly 10 digits
		return phoneNumber >= 1000000000 && phoneNumber <= 9999999999
	}

	// If the field is neither a string, uint64, nor int, the validation fails
	return false
}

func validateSOBONamePattern(f1 validator.FieldLevel) bool {
	// Define the regex pattern
	// ^[A-Za-z] -> Start with a letter
	// [A-Za-z\s]{1,48} -> 1 to 48 letters or spaces
	// [A-Za-z]$ -> End with a letter
	//pattern := `^[A-Za-z][A-Za-z\s]{1,48}[A-Za-z]$`

	return ValidateWithGlobalRegex(f1, SOBONamePattern)
}
func validatePANNumberPattern(fl validator.FieldLevel) bool {
	// regex pattern for PAN number (5 letters followed by 4 digits followed by 1 letter)
	//pattern := `^[A-Z]{5}[0-9]{4}[A-Z]$`

	return ValidateWithGlobalRegex(fl, PANNumberPattern)
}
func validateVehicleRegistrationNumberPattern(fl validator.FieldLevel) bool {
	// Define the regex pattern for vehicle registration number
	//pattern := `^[A-Z]{2}\d{2}[A-Z]{1,2}\d{4,7}$`
	return ValidateWithGlobalRegex(fl, VehicleRegistrationNumberPattern)
}
func validateBarCodeNumberPattern(fl validator.FieldLevel) bool {

	// Define the regex pattern for vehicle registration number
	//pattern := `^[A-Z]{2}\d{6,12}[A-Z]{2}$`
	return ValidateWithGlobalRegex(fl, BarCodeNumberPattern)
}
func customValidateGLCodePattern(fl validator.FieldLevel) bool {
	//pattern := `^GL\d{11}$`
	return ValidateWithGlobalRegex(fl, GLCodePattern)
}
func timeStampValidatePattern(f1 validator.FieldLevel) bool {
	//dateTimeRegex := regexp.MustCompile(`^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-(\d{4}) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$`)
	return ValidateWithGlobalRegex(f1, timeStampPattern)
}
func validateAnyStringLengthto50Pattern(fl validator.FieldLevel) bool {
	//pattern := `^[a-zA-Z][a-zA-Z0-9]{0,48}[a-zA-Z]$`
	// Check if the string matches the regex pattern
	return ValidateWithGlobalRegex(fl, customValidateAnyStringLengthto50Pattern)
}
func validatedateyyyymmddPattern(fl validator.FieldLevel) bool {
	//pattern := `^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`
	// Check if the date matches the regex pattern
	return ValidateWithGlobalRegex(fl, dateyyyymmddPattern)

}
func validatedateddmmyyyyPattern(fl validator.FieldLevel) bool {
	//pattern := `^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-\d{4}$`

	// Check if the date matches the regex pattern
	return ValidateWithGlobalRegex(fl, dateddmmyyyyPattern)

}
func validateEmployeeIDPattern(fl validator.FieldLevel) bool {
	//pattern := `^\d{8}$`
	return ValidateWithGlobalRegex(fl, EmployeeIDPattern)
}
func validateGSTINPattern(fl validator.FieldLevel) bool {

	// Define the regex pattern for GSTIN validation
	//pattern := `^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[A-Z0-9]{1}[Z]{1}[0-9]{1}$`

	return ValidateWithGlobalRegex(fl, GSTINPattern)
}

func ValidatePhoneNumberStringPattern(fl validator.FieldLevel) bool {
	return ValidateWithGlobalRegex(fl, PhoneNumberStringPattern)
}
func validateBagIdPattern(fl validator.FieldLevel) bool {
	return ValidateWithGlobalRegex(fl, bagIdPattern)
}

//***********************************************

func validatePRANPattern(fl validator.FieldLevel) bool {
	// Handle the case where the PRAN is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match exactly 12 digits
		//pattern := `^\d{12}$`

		return ValidateWithGlobalRegex(fl, PRANPattern)
	}

	// Handle the case where the PRAN is an int64
	if pranInt, ok := fl.Field().Interface().(int64); ok {
		// Check if the int64 falls within the 12-digit range
		return pranInt >= 100000000000 && pranInt <= 999999999999
	}

	// If the field is neither a valid string nor a valid integer, the validation fails
	return false
}

func validateOfficeCustomerPattern(fl validator.FieldLevel) bool {
	// Regular expression to allow only alphanumeric characters and spaces
	// This will disallow special characters like @, #, $, %, etc.
	//pattern := `^[a-zA-Z0-9\s]+$`

	// Get the field value and convert it to a string
	officeCustomer, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	// Check if the length of the string is within 50 characters
	if len(officeCustomer) > 50 {
		return false
	}

	// Check if the office_customer string matches the allowed pattern
	return ValidateWithGlobalRegex(fl, OfficeCustomerPattern)
}

func validateReceiverKYCReferencePattern(fl validator.FieldLevel) bool {

	// Define a regex pattern to match the format KYCREF followed by up to 44 alphanumeric characters
	//pattern := `^KYCREF[A-Z0-9]{0,44}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, ReceiverKYCReferencePattern)
}

func validateApplicationIDPattern(fl validator.FieldLevel) bool {
	// Define a regex pattern to match the format <3 uppercase letters><12 digits with hyphen>
	//pattern := `^[A-Z]{3}\d{8}-\d{3}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, ApplicationIDPattern)
}

func validateFacilityIDPattern(fl validator.FieldLevel) bool {

	// Define a regex pattern to match the format <2 uppercase letters><11 digits>
	//pattern := `^[A-Z]{2}\d{11}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, FacilityIDPattern)
}

func validateCustomerIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the value is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match a 10-digit number
		//pattern := `^\d{10}$`
		// Check if the string matches the pattern
		return ValidateWithGlobalRegex(fl, CustomerIDPattern)
	}

	// Handle the case where the value is an integer
	if customerIDInt, ok := fl.Field().Interface().(int); ok {
		// Convert the integer to a string
		customerIDStr := strconv.Itoa(customerIDInt)

		// Check if the integer has exactly 10 digits
		return len(customerIDStr) == 10
	}

	// If the field is neither a string nor an integer, validation fails
	return false
}

func validateProductCodePattern(fl validator.FieldLevel) bool {
	// Assume the fl value is always a string

	// Define a regex pattern to match the format <3 uppercase letters><12 digits>
	//pattern := `^[A-Z]{3}\d{12}$`

	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, ProductCodePattern)
}

func validatePLIOfficeIDPattern(fl validator.FieldLevel) bool {
	// Assume the fl value is always a string

	// Define a regex pattern to match the format <3 uppercase letters><10 digits>
	//pattern := `^[A-Z]{3}\d{10}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, PLIOfficeIDPattern)
}

func validateSOLIDPattern(fl validator.FieldLevel) bool {
	// Assume the fl value is always a string

	// Define a regex pattern to match the format <6 digits pincode><2 digits office type number>
	//pattern := `^\d{6}\d{2}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, SOLIDPattern)
}

func validatePosBookingOrderNumberPattern(fl validator.FieldLevel) bool {
	// Assume the fl value is always a string

	// Define a regex pattern to match the format <2 uppercase letters><19 digits>
	//pattern := `^[A-Z]{2}\d{19}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, PosBookingOrderNumberPattern)
}

func validateCSIFacilityIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the csi_facility_id is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <2 uppercase letters><11 digit numeric>
		//pattern := `^[A-Z]{2}\d{11}$`
		// Check if the csi_facility_id matches the pattern
		return ValidateWithGlobalRegex(fl, CSIFacilityIDPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

func validateBankIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the value is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match a string with up to 50 characters consisting of uppercase letters and digits
		//pattern := `^[A-Z0-9]{1,50}$`
		// Check if the string matches the pattern
		return ValidateWithGlobalRegex(fl, BankIDPattern)
	}

	// If the field is not a string, validation fails
	return false
}

func validateOfficeCustomerIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the value is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match any string with up to 50 characters

		//pattern := `^[a-zA-Z0-9\-]{1,50}$`
		// Check if the string matches the pattern
		return ValidateWithGlobalRegex(fl, OfficeCustomerIDPattern)
	}

	// If the field is not a string, validation fails
	return false
}

func validatePaymentTransIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the payment_trans_id is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <2digit><uuid v4>
		//pattern := `^\d{2}[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`

		// Check if the payment_trans_id matches the pattern
		return ValidateWithGlobalRegex(fl, PaymentTransIDPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

func validatePLIIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the pli_id is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <3 uppercase letters><10 digit numeric>
		//pattern := `^[A-Z]{3}\d{10}$`
		// Check if the awbnumber matches the pattern
		return ValidateWithGlobalRegex(fl, PLIIDPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

func validatePNRNoPattern(fl validator.FieldLevel) bool {

	// Handle the case where the pnr_no is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format
		//pattern := `^[A-Z]{3}\d{6}$`
		// Check if the pnr_no matches the pattern
		return ValidateWithGlobalRegex(fl, PNRNoPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

func validateAWBNumberPattern(fl validator.FieldLevel) bool {
	// Handle the case where the awbnumber is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <4 uppercase letters><9 digit numeric>
		//pattern := `^[A-Z]{4}\d{9}$`

		// Check if the awbnumber matches the pattern
		return ValidateWithGlobalRegex(fl, AWBNumberPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

func ValidateOrderNumberPattern(fl validator.FieldLevel) bool {
	// Handle the case where the order_number is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <2 uppercase letters><19 digit numeric>
		//pattern := `^[A-Z]{2}\d{19}$`
		// Check if the order_number matches the pattern
		return ValidateWithGlobalRegex(fl, OrderNumberPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

func validateBankUserIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the bank_user_id is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that ensures the bank_user_id is alphanumeric and between 1 to 50 characters
		//pattern := `^[A-Z0-9]{1,50}$`

		// Check if the bank_user_id matches the pattern
		return ValidateWithGlobalRegex(fl, BankUserIDPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

func validateHONamePattern(fl validator.FieldLevel) bool {
	// Handle the case where the ho_name is a string
	if hoName, ok := fl.Field().Interface().(string); ok {
		// Check if the ho_name is not empty and has a maximum length of 50 characters
		if len(hoName) == 0 || len(hoName) > 50 {
			return false
		}

		// Define a regex pattern that disallows special characters @,#/$%!^&*()<>:;"{}[]
		// specialCharPattern := `[!@#$%^&*()<>:;"{}[\]\\]`
		// regex := regexp.MustCompile(specialCharPattern)

		// Check if the ho_name contains any special characters
		if specialCharPattern.MatchString(hoName) {
			return false
		}

		// If all checks pass, return true
		return true
	}

	// If the field is not a string, the validation fails
	return false
}
func validatePinCodeGlobal(fl validator.FieldLevel) bool {
	zipCode := fl.Field().String()

	// Check if the length is 6
	if len(zipCode) != 6 {
		return false
	}
	// Check if the pin code contains only digits
	if _, err := strconv.Atoi(zipCode); err != nil {
		return false
	}

	// Check if the first digit is in the range 1 to 9
	firstDigit, err := strconv.Atoi(string(zipCode[0]))
	if err != nil || firstDigit < 1 || firstDigit > 9 {
		return false
	}

	// Check if the last five digits are not all zeros
	lastFiveDigits := zipCode[1:6]
	//allZerosRegex := regexp.MustCompile("^0+$")
	if allZerosRegex.MatchString(lastFiveDigits) {
		return false
	}
	// Check if the last three digits are not all zeros
	lastThreeDigits := zipCode[3:6]
	if allZerosRegex.MatchString(lastThreeDigits) {
		return false
	}
	return true

}
func validateCustomFlightNo(fl validator.FieldLevel) bool {
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format
		//pattern := `^[A-Z]{3}\d{6}$`
		// Check if the pnr_no matches the pattern
		return ValidateWithGlobalRegex(fl, FlightNopattern)
	}

	// If the field is not a string, the validation fails
	return false

}

// //////////////////////////////////////////////////without regex functions
func customofficeidGlobal(fl validator.FieldLevel) bool {
	// Handle the case where the officeId is an int
	if officeId, ok := fl.Field().Interface().(int); ok {
		return officeId >= 1000000 && officeId <= 99999999
	}

	// Handle the case where the officeId is a uint64
	if officeId, ok := fl.Field().Interface().(uint64); ok {
		return officeId >= 1000000 && officeId <= 99999999
	}

	// Handle the case where the officeId is a string
	if officeIdStr, ok := fl.Field().Interface().(string); ok {
		// Check if the string is not empty and contains only digits
		if len(officeIdStr) >= 7 && len(officeIdStr) <= 8 {
			if _, err := strconv.ParseUint(officeIdStr, 10, 64); err == nil {
				return true
			}
		}
	}

	// If the field is neither an int, uint64, nor a valid string, the validation fails
	return false
}
func customTrainNoGlobal(fl validator.FieldLevel) bool {
	// Attempt to get the train number as a uint64
	if trainNo, ok := fl.Field().Interface().(uint64); ok {
		// Check if the train number has exactly 5 digits
		return trainNo >= 10000 && trainNo <= 99999
	}

	// Attempt to get the train number as a string
	if trainNoStr, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match exactly 5 digits
		//regex := regexp.MustCompile(`^\d{5}$`)
		// Check if the string matches the regex pattern
		return trainNoPattern.MatchString(trainNoStr)
	}

	// If the value is neither a 5-digit uint64 nor a 5-digit string, validation fails
	return false
}

// seating capacity in a train
func customSCSGlobal(fl validator.FieldLevel) bool {
	// Get the train number from the field
	seating, ok := fl.Field().Interface().(uint64)
	if !ok {
		// If it's not a uint64, the validation fails
		return false
	}
	// Check if the strength  has exactly  1 to 4 digits
	return seating >= 1 && seating <= 9999
}

// Circle_id is validation for integer . example: 90000013 starting with 7 digit
func validateCircleIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the Circle_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 9000001 && usercode <= 9999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 9000001 && usercode <= 9999999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// tariff_id  is validation for integer . example: 1234567890 10 digit
func validateTariffIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the tariff_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 1000000000 && usercode <= 9999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 1000000000 && usercode <= 9999999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// CIF Number is validation for integer . example: 327711299
func validateCIFNumGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the CIF is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 100000000 && usercode <= 999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 100000000 && usercode <= 999999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// Contract Number is validation for integer(8) . example: 40057692
func validateContractNumGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the ContractNum is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 10000000 && usercode <= 99999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 10000000 && usercode <= 99999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// region_id is validation for integer(10) . example: 9000001
func validateRegionIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the region_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 1000000 && usercode <= 9999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 1000000 && usercode <= 9999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// vas_id is validation for integer(10) . example: 1234567
func validateVasIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the vas_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {
		// Check if the vas_id has exactly 10 digits
		return usercode >= 1000000 && usercode <= 9999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 1000000 && usercode <= 9999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// usercode is validation for integer(10) . example: 10181686
func validateUserCodeGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the usercode is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {
		// Check if the usercode has exactly 10 digits
		return usercode >= 10000000 && usercode <= 99999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 10000000 && usercode <= 99999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// ho_id validation for 7 digit integer or 7 digit string
func validateHOIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the ValidateHOID  is a uint64
	if gNumber, ok := fl.Field().Interface().(uint64); ok {
		// Check if the ho_id  has exactly 7 digits
		return gNumber >= 1000000 && gNumber <= 9999999
	}

	// Handle the case where the ValidateHOID  is an int
	if gNumber, ok := fl.Field().Interface().(int); ok {
		// Check if the ho_id has exactly 7 digits
		return gNumber >= 1000000 && gNumber <= 9999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if gNumberStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if gNumber, err := strconv.ParseInt(gNumberStr, 10, 64); err == nil {
			return gNumber >= 1000000 && gNumber <= 9999999
		}
	}
	// If the field is neither a string, uint64, nor int, the validation fails
	return false
}

// account_no validation for 10 digit integer or 10 digit string
func validateAccountNoGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the ValidateAccountNo  is a uint64
	if gNumber, ok := fl.Field().Interface().(uint64); ok {
		// Check if the account_no  has exactly 10 digits
		return gNumber >= 1000000000 && gNumber <= 9999999999
	}

	// Handle the case where the ValidateAccountNo  is an int
	if gNumber, ok := fl.Field().Interface().(int); ok {
		// Check if the account_no has exactly 10 digits
		return gNumber >= 1000000000 && gNumber <= 9999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if gNumberStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if gNumber, err := strconv.ParseInt(gNumberStr, 10, 64); err == nil {
			return gNumber >= 1000000000 && gNumber <= 9999999999
		}
	}
	// If the field is neither a string, uint64, nor int, the validation fails
	return false
}
