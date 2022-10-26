package slices

// Contains reports whether v is present in s.
func Contains[E comparable](s []E, v E) bool {
	for i := range s {
		if v == s[i] {
			return true
		}
	}
	return false
}

// Extend extends the input slice by n elements. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func Extend[E any](in []E, n int) (head, tail []E) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]E, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
