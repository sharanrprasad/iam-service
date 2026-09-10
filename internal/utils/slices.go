package utils

// ContainsAll checks if the 'main' slice contains all elements of the 'sub' slice.
func ContainsAll[T comparable](main []T, sub []T) bool {
	mainMap := make(map[T]struct{}, len(main))
	for _, val := range main {
		mainMap[val] = struct{}{}
	}
	for _, val := range sub {
		if _, exists := mainMap[val]; !exists {
			return false
		}
	}
	return true
}
