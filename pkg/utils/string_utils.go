package utils

// IsASCII checks if all characters in the input byte array are ASCII characters.
func IsASCII(input []byte) bool {
	for _, b := range input {
		if b > 127 {
			return false
		}
	}
	return true
}
