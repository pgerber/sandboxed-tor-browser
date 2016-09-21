// main.go - sandboxed-tor-browser
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

package main

import (
	"log"
	"os"
	"os/signal"
	"path"
	"syscall"

	"cmd/sandboxed-tor-browser/internal/config"
	"cmd/sandboxed-tor-browser/internal/installer"
	"cmd/sandboxed-tor-browser/internal/sandbox"
)

type lockFile struct {
	f *os.File
}

func (l *lockFile) unlock() {
	defer l.f.Close()
	os.Remove(l.f.Name())
}

func createLockFile(cfg *config.Config) (*lockFile, error) {
	const lockFileName = "lock"

	l := new(lockFile)
	pathName := path.Join(cfg.RuntimeDir(), lockFileName)

	var err error
	l.f, err = os.OpenFile(pathName, os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func makeDirectories(cfg *config.Config) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
	}()

	var dirs []string
	dirs = append(dirs, cfg.UserDataDir())
	dirs = append(dirs, cfg.RuntimeDir())

	for _, d := range dirs {
		if err = os.MkdirAll(d, os.ModeDir|0700); err != nil {
			return
		}
	}
	return nil
}

func main() {
	// Load the configuration file.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}
	log.Printf("config: %v", cfg)

	// Create all the directories where files are stored if missing.
	if err = makeDirectories(cfg); err != nil {
		log.Fatalf("failed to create directories: %v", err)
	}

	// Install the signal handlers before acquiring the lock.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, syscall.SIGTERM)

	// Aquire the lock file.
	lock, err := createLockFile(cfg)
	if err != nil {
		log.Fatalf("failed to create lock file: %v", err)
	}
	defer lock.unlock()

	// Install/Update in a separage goroutine so cleanup happens.
	doneCh := make(chan interface{})
	go func() {
		// Install/Update as appropriate.
		if err := installer.Install(cfg); err != nil {
			log.Printf("failed to install/update: %v", err)
			return
		}

		// Launch sandboxed tor browser.
		if cmd, err := sandbox.RunTorBrowser(cfg); err != nil {
			log.Printf("failed to spawn sandbox: %v", err)
		} else {
			cmd.Wait()
		}
		doneCh <- true
	}()

	// Wait for the actual work to finish, or a fatal signal to be received.
	select {
	case _ = <-doneCh:
		// Goroutine terminated.
	case sig := <-sigCh:
		// Caught a signal handler.
		log.Printf("exiting on signal: %v", sig)
	}
}
