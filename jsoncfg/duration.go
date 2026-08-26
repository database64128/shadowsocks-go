package jsoncfg

import "time"

// Duration is [time.Duration] but uses its string representation for marshaling and unmarshaling.
type Duration time.Duration

// Value returns the duration as a [time.Duration].
func (d Duration) Value() time.Duration {
	return time.Duration(d)
}

// AppendText implements [encoding.TextAppender].
func (d Duration) AppendText(b []byte) ([]byte, error) {
	return append(b, time.Duration(d).String()...), nil
}

// MarshalText implements [encoding.TextMarshaler].
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (d *Duration) UnmarshalText(text []byte) error {
	duration, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}
