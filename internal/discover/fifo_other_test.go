//go:build !unix

package discover

import "errors"

func makeFIFO(string, uint32) error {
	return errors.New("FIFOs are not supported on this platform")
}
