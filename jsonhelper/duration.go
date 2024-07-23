package jsonhelper

import "time"

// Duration is [time.Duration] but implements [encoding.TextMarshaler] and [encoding.TextUnmarshaler].
type Duration time.Duration

// Value returns the duration as [time.Duration].
func (d Duration) Value() time.Duration {
	return time.Duration(d)
}

// MarshalText implements [encoding.TextMarshaler.MarshalText].
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler.UnmarshalText].
func (d *Duration) UnmarshalText(text []byte) error {
	duration, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}
