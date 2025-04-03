//go:build darwin

package platform

import (
	"context"

	"github.com/jnesss/bpf-recorder/binary"
	"github.com/jnesss/bpf-recorder/database"
)

type DarwinBPFMonitor struct {
	db          *database.DB
	binaryCache *binary.Cache
}

func NewBPFMonitor(db *database.DB, binaryCache *binary.Cache, cgroupPath string) (BPFMonitor, error) {
	return &DarwinBPFMonitor{
		db:          db,
		binaryCache: binaryCache,
	}, nil
}

func (m *DarwinBPFMonitor) Start(context.Context) error {
	// No-op on Darwin
	return nil
}

func (m *DarwinBPFMonitor) Stop() error {
	// No-op on Darwin
	return nil
}
