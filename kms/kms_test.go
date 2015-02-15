package kms

import (
	"testing"
	// . "github.com/Inflatablewoman/go-kms/gocheck2"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type KMSSuite struct {
}

var _ = Suite(&KMSSuite{})

func (s *KMSSuite) SetUpSuite(c *C) {
}

// Test down the suite
func (s *KMSSuite) TearDownSuite(c *C) {
}

func (s *KMSSuite) TestBasic(c *C) {
	BasicTest()
}
