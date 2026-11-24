package service

import "time"

// Clock abstracts the current time for deterministic tests.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

// NewSystemClock returns a UTC clock backed by time.Now.
func NewSystemClock() Clock {
	return systemClock{}
}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}
