package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// getOriginalUser gets the user who invoked sudo
func getOriginalUser() (*user.User, error) {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		return nil, fmt.Errorf("SUDO_USER environment variable not found")
	}
	return user.Lookup(sudoUser)
}

// dropPrivileges drops root privileges to the original user
func dropPrivileges() error {
	u, err := getOriginalUser()
	if err != nil {
		return fmt.Errorf("could not get original user: %v", err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid: %v", err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("invalid gid: %v", err)
	}

	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("could not drop group privileges: %v", err)
	}

	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("could not drop user privileges: %v", err)
	}

	return nil
}
