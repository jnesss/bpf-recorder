package binary

import (
    "crypto/md5"
    "encoding/hex"
    "io"
    "os"
)

// CalculateMD5 generates an MD5 hash of a file
func CalculateMD5(filePath string) (string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return "", err
    }
    defer file.Close()

    hash := md5.New()
    if _, err := io.Copy(hash, file); err != nil {
        return "", err
    }

    return hex.EncodeToString(hash.Sum(nil)), nil
}
