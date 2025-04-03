//go:build darwin

package platform

import (
	"context"

	"github.com/jnesss/bpf-recorder/binary"
	"github.com/jnesss/bpf-recorder/database"
	"github.com/jnesss/bpf-recorder/process"
)

type DarwinBPFMonitor struct {
	db          *database.DB
	binaryCache *binary.Cache
	processMap  *process.ProcessMap
}

func NewBPFMonitor(config *MonitorConfig) (BPFMonitor, error) {
	return &DarwinBPFMonitor{
		db:          config.DB.(*database.DB),
		binaryCache: config.BinaryCache.(*binary.Cache),
		processMap:  config.ProcessMap,
	}, nil
}

func (m *DarwinBPFMonitor) GetProcessMap() *process.ProcessMap {
	return m.processMap
}

func (m *DarwinBPFMonitor) Start(context.Context) error {
	// No-op on Darwin
	return nil
}

func (m *DarwinBPFMonitor) Stop() error {
	// No-op on Darwin
	return nil
}
