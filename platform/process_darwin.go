//go:build darwin

package platform

import (
	"github.com/jnesss/bpf-recorder/process"
)

// LookupCmdline is a no-op on Darwin
func LookupCmdline(_ interface{}, _ uint32) (string, error) {
	return "", nil
}

// EnrichProcessEvent is a no-op on Darwin
func EnrichProcessEvent(_ *ProcessEvent, _ *process.ProcessMap, _ interface{}) *process.ProcessInfo {
	return nil
}
