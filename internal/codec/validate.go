package codec

import "errors"

// ValidateStrictSortedIDs rejects empty, zero, duplicate, or unsorted IDs.
func ValidateStrictSortedIDs[T uint32Value](ids []T) error {
	if len(ids) == 0 {
		return errors.New("party set is empty")
	}
	var last T
	for i, id := range ids {
		if id == 0 {
			return errors.New("party id 0 is reserved")
		}
		if i > 0 && id <= last {
			return errors.New("party ids must be strictly increasing")
		}
		last = id
	}
	return nil
}
