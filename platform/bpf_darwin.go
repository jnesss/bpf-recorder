//go:build darwin
package platform

type DarwinBPFMonitor struct {
    db          *DB
    binaryCache *BinaryCache
}

func NewBPFMonitor(db *DB, binaryCache *BinaryCache, cgroupPath string) (*DarwinBPFMonitor, error) {
    return &DarwinBPFMonitor{
        db:          db,
        binaryCache: binaryCache,
    }, nil
}

func (m *DarwinBPFMonitor) Start() error {
    // No-op on Darwin
    return nil
}

func (m *DarwinBPFMonitor) Stop() error {
    // No-op on Darwin
    return nil
}
