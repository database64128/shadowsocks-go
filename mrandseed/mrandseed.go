// Package mrandseed can be imported by users of the [math/rand]
// global source to seed it with the current unix nano time.
package mrandseed

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}
