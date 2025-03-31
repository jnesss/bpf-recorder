package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	lru "github.com/hashicorp/golang-lru"
)

// BinaryCache provides efficient lookup for binary presence with LRU eviction
type BinaryCache struct {
	cache   *lru.Cache
	binsDir string
}

// NewBinaryCache creates a size-constrained binary cache with LRU eviction
func NewBinaryCache(size int, binsDir string) (*BinaryCache, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	// Drop privileges before doing anything with the bins dir
	if err := dropPrivileges(); err != nil {
		return nil, fmt.Errorf("failed to drop privileges: %v", err)
	}

	// Create bins directory if it doesn't exist
	if err := os.MkdirAll(binsDir, 0755); err != nil {
		return nil, err
	}

	return &BinaryCache{
		cache:   cache,
		binsDir: binsDir,
	}, nil
}

// HasBinary checks if a binary hash exists in the cache
func (c *BinaryCache) HasBinary(hash string) bool {
	_, found := c.cache.Get(hash)
	return found
}

// AddBinary adds a binary hash to the cache
func (c *BinaryCache) AddBinary(hash string) {
	c.cache.Add(hash, true)
}

// GetBinaryPath returns the path where a binary with given hash would be stored
func (c *BinaryCache) GetBinaryPath(hash string) string {
	prefix := hash[:2]
	return filepath.Join(c.binsDir, prefix, hash+".bin")
}

// StoreBinary copies a binary to the storage location based on its hash
func (c *BinaryCache) StoreBinary(sourcePath, hash string) error {
	// Copy the file
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	// Drop privileges before doing anything with the bins dir
	if err := dropPrivileges(); err != nil {
		return fmt.Errorf("failed to drop privileges: %v", err)
	}

	// Create directory if needed
	prefix := hash[:2]
	dirPath := filepath.Join(c.binsDir, prefix)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return err
	}

	// Set the destination path
	destPath := filepath.Join(dirPath, hash+".bin")
	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Set read-only permissions
	if err := destFile.Chmod(0444); err != nil {
		log.Printf("Warning: Failed to set permissions on binary: %v", err)
	}

	// Copy the content
	_, err = io.Copy(destFile, sourceFile)
	return err
}
