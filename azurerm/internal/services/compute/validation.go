package compute

import "github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/validate"

func ValidateLinuxName(i interface{}, k string) ([]string, []error) {
	// TODO: implement me
	// The value must not be empty.
	// The value can only contain alphanumeric characters and cannot start with a number.
	// Azure resource names cannot contain special characters \/""[]:|<>+=;,?*@& or begin with '_' or end with '.' or '-'
	// The value must be between 1 and 64 characters long.
	return validate.NoEmptyStrings(i, k)
}
