package conn

import "testing"

type dialResultTestCase struct {
	name                   string
	err                    error
	expectedDialResultCode DialResultCode
}

func TestDialResultFromError(t *testing.T) {
	for _, c := range dialResultTestCases {
		t.Run(c.name, func(t *testing.T) {
			if got := DialResultFromError(c.err); got.Code != c.expectedDialResultCode || got.Err != c.err {
				t.Errorf("DialResultFromError(%v) = %v, want %v", c.err, got, c.expectedDialResultCode)
			}
		})
	}
}
