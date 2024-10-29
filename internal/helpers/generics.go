package helpers

import "slices"

func SameStringSlice(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for _, elem := range slice1 {
		if !slices.Contains(slice2, elem) {
			return false
		}
	}
	for _, elem := range slice2 {
		if !slices.Contains(slice1, elem) {
			return false
		}
	}
	return true
}

func ElemInStringSlice(elem string, sSlice []string) bool {
	for _, e := range sSlice {
		if e == elem {
			return true
		}
	}
	return false
}
