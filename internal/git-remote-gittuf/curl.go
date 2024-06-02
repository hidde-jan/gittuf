// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/gittuf/gittuf/internal/rsl"
)

func handleCurl(remoteName, url string) (map[string]string, bool, error) {
	helper := exec.Command("git-remote-http", remoteName, url)

	helper.Stderr = os.Stderr

	// We want to inspect the helper's stdout for the gittuf ref statuses
	helperStdOutPipe, err := helper.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	helperStdOut := &logReadCloser{name: "git-remote-http stdout", readCloser: helperStdOutPipe}

	// We want to interpose with the helper's stdin by passing in extra refs
	// etc
	helperStdInPipe, err := helper.StdinPipe()
	if err != nil {
		return nil, false, err
	}
	helperStdIn := &logWriteCloser{name: "git-remote-http stdin", writeCloser: helperStdInPipe}

	if err := helper.Start(); err != nil {
		return nil, false, err
	}

	stdInScanner := &logScanner{name: "git-remote-gittuf stdin", scanner: bufio.NewScanner(os.Stdin)}
	stdInScanner.Split(splitInput)

	var (
		gittufRefsTips = map[string]string{}
		pushCommands   = [][]byte{}
		service        string
		isPush         bool
	)

	currentState := start // top level "menu" for the helper
	for stdInScanner.Scan() {
		command := stdInScanner.Bytes()

	alreadyScanned:

		switch currentState {
		case start:
			log("state: start")
			// Handle "top level" commands here
			switch {
			case bytes.HasPrefix(command, []byte("stateless-connect")):
				log("cmd: stateless-connect")
				commandSplit := bytes.Split(bytes.TrimSpace(command), []byte(" "))
				service = string(commandSplit[1])
				log("found service", service)
				currentState = serviceRouter // head to the service router next

				if _, err := helperStdIn.Write(command); err != nil {
					return nil, false, err
				}

				// Receive the initial info sent by the service
				helperStdOutScanner := bufio.NewScanner(helperStdOut)
				helperStdOutScanner.Split(splitOutput)

				for helperStdOutScanner.Scan() {
					output := helperStdOutScanner.Bytes()

					if _, err := os.Stdout.Write(output); err != nil {
						return nil, false, err
					}

					if bytes.Equal(output, flushPkt) {
						break
					}
				}

			case bytes.HasPrefix(command, []byte("list for-push")): // we don't bother with list atm because fetch uses upload-pack's ls-refs and compares locals
				log("cmd: list for-push")
				if _, err := helperStdIn.Write(command); err != nil {
					return nil, false, err
				}

				helperStdOutScanner := bufio.NewScanner(helperStdOut)
				helperStdOutScanner.Split(splitOutput)

				log("list for-push returned:")
				for helperStdOutScanner.Scan() {
					output := helperStdOutScanner.Bytes()

					refAdSplit := strings.Split(strings.TrimSpace(string(output)), " ")
					if len(refAdSplit) >= 2 {
						if strings.HasPrefix(refAdSplit[1], gittufRefPrefix) {
							gittufRefsTips[refAdSplit[1]] = refAdSplit[0]
						}
					}

					if _, err := os.Stdout.Write(output); err != nil {
						return nil, false, err
					}

					if bytes.Equal(output, flushPkt) {
						break
					}
				}

			case bytes.HasPrefix(command, []byte("push")): // multiline input
				log("cmd: push")
				isPush = true

				for {
					if bytes.Equal(command, []byte("\n")) {
						log("adding gittuf RSL entries if remote is gittuf-enabled")
						// Fetch remote RSL if needed
						// cmd := exec.Command("git", "rev-parse", rsl.Ref)
						// output, err := cmd.Output()
						// if err != nil {
						// 	return nil, false, err
						// }
						// localRSLTip := string(bytes.TrimSpace(output))
						// remoteRSLTip := gittufRefsTips[rsl.Ref]
						// if localRSLTip != remoteRSLTip {
						// 	// TODO: This just assumes the local RSL is behind
						// 	// the remote RSL. With the transport in use, the
						// 	// local should never be ahead of remote, but we
						// 	// should verify.

						// 	var fetchStdOut bytes.Buffer
						// 	cmd := exec.Command("git", "fetch", remoteName, fmt.Sprintf("%s:%s", rsl.Ref, rsl.Ref))
						// 	cmd.Stdout = &fetchStdOut

						// }

						for _, pushCommand := range pushCommands {
							if len(gittufRefsTips) != 0 {
								refSpec := string(bytes.Split(bytes.TrimSpace(pushCommand), []byte{' '})[1])
								refSpecSplit := strings.Split(refSpec, ":")
								srcRef := refSpecSplit[0]
								dstRef := refSpecSplit[1]

								if !strings.HasPrefix(dstRef, gittufRefPrefix) {
									cmd := exec.Command("gittuf", "rsl", "record", "--dst-ref", dstRef, srcRef)
									cmd.Stderr = os.Stderr
									cmd.Stdout = os.Stderr
									if err := cmd.Run(); err != nil {
										return nil, false, err
									}
								}
							}

							if _, err := helperStdIn.Write(pushCommand); err != nil {
								return nil, false, err
							}
						}

						// If remote is gittuf-enabled, also push the RSL
						if len(gittufRefsTips) != 0 {
							if _, err := helperStdIn.Write([]byte(fmt.Sprintf("push %s:%s\n", rsl.Ref, rsl.Ref))); err != nil {
								return nil, false, err
							}
						}

						// Add newline to indicate end of push batch
						if _, err := helperStdIn.Write([]byte("\n")); err != nil {
							return nil, false, err
						}

						break
					}

					pushCommands = append(pushCommands, command)

					// Read in the next statement in the push batch
					if !stdInScanner.Scan() {
						// This should really not be reachable as we ought to
						// get the newline and break first from our invoker.
						break
					}
					command = stdInScanner.Bytes()
				}

				helperStdOutScanner := bufio.NewScanner(helperStdOut)
				helperStdOutScanner.Split(splitOutput)

				for helperStdOutScanner.Scan() {
					output := helperStdOutScanner.Bytes()

					if !bytes.Contains(output, []byte(gittufRefPrefix)) {
						// we do this because git (at the very top level)
						// inspects all the refs it's been asked to push and
						// tracks their current status it never does this for
						// the rsl ref, because only the transport is pushing
						// that ref if we don't filter this out, it knows
						// refs/gittuf/rsl got pushed, it knows _what_ the
						// previous rsl tip was (by talking to the remote in
						// list for-push) but it doesn't actually know the new
						// tip of the rsl that was pushed because this is loaded
						// before the transport is ever invoked.
						if _, err := os.Stdout.Write(output); err != nil {
							return nil, false, err
						}
					}

					if bytes.Equal(output, flushPkt) {
						break
					}
				}
			default:
				log("state: other-helper-command")
				// Pass through other commands we don't want to interpose to the
				// curl helper
				if _, err := helperStdIn.Write(command); err != nil {
					return nil, false, err
				}

				// Receive the initial info sent by the service
				helperStdOutScanner := bufio.NewScanner(helperStdOut)
				helperStdOutScanner.Split(splitOutput)

				for helperStdOutScanner.Scan() {
					output := helperStdOutScanner.Bytes()

					if _, err := os.Stdout.Write(output); err != nil {
						return nil, false, err
					}

					if bytes.Equal(output, flushPkt) {
						break
					}
				}
			}

		case serviceRouter:
			log("state: service-router")
			isPacketMode = true
			switch service { //nolint:gocritic
			case gitUploadPack: // fetching from remote
				if bytes.Contains(command, []byte("command=ls-refs")) {
					currentState = lsRefs
				} else if bytes.Contains(command, []byte("command=fetch")) {
					currentState = requestingWants
				}
				// TODO: see if we need other services, right now it looks like no
			}

			if _, err := helperStdIn.Write(command); err != nil {
				return nil, false, err
			}

			// Right now, we don't need to wait for a response here, we check
			// what command of the git service we're invoking and go to that
			// state, this is almost a "routing" state. THIS MAY CHANGE!

		case lsRefs:
			log("state: ls-refs")
			if bytes.Equal(command, flushPkt) {
				// add the gittuf ref-prefix right before the flushPkt
				log("adding ref-prefix for refs/gittuf/")
				gittufRefPrefixCommand := fmt.Sprintf("ref-prefix %s\n", gittufRefPrefix)
				if _, err := helperStdIn.Write(packetEncode(gittufRefPrefixCommand)); err != nil {
					return nil, false, err
				}

				currentState = lsRefsResponse
			}

			if _, err := helperStdIn.Write(command); err != nil {
				return nil, false, err
			}

			// after writing flush to stdin, we can get the advertised refs
			if currentState == lsRefsResponse {
				helperStdOutScanner := bufio.NewScanner(helperStdOut)
				helperStdOutScanner.Split(splitOutput)

				for helperStdOutScanner.Scan() {
					output := helperStdOutScanner.Bytes()

					if !bytes.Equal(output, flushPkt) && !bytes.Equal(output, endOfReadPkt) {
						refAd := strings.TrimSpace(string(output)[4:]) // remove the length prefix
						if i := strings.IndexByte(refAd, '\x00'); i > 0 {
							// this checks if the gittuf entry is the very first
							// returned (unlikely because of HEAD)
							refAd = refAd[:i] // drop everything from null byte onwards
						}
						refAdSplit := strings.Split(refAd, " ")

						if strings.HasPrefix(refAdSplit[1], gittufRefPrefix) {
							gittufRefsTips[refAdSplit[1]] = refAdSplit[0]
						}
					}

					if _, err := os.Stdout.Write(output); err != nil {
						return nil, false, err
					}

					if bytes.Equal(output, endOfReadPkt) {
						break
					}
				}

				currentState = serviceRouter // go back to service's "router"
			}

		case requestingWants:
			log("state: requesting-wants")
			wantsDone := false
			if bytes.Equal(command, flushPkt) {
				if !wantsDone {
					// Write gittuf wants
					log("adding gittuf wants")
					for _, tip := range gittufRefsTips {
						wantCmd := fmt.Sprintf("want %s\n", tip)
						if _, err := helperStdIn.Write(packetEncode(wantCmd)); err != nil {
							return nil, false, err
						}
					}
					wantsDone = true

					// FIXME: does this work for incremental fetches?
					currentState = packfileIncoming
				}
			}

			if _, err := helperStdIn.Write(command); err != nil {
				return nil, false, err
			}

			if currentState == packfileIncoming {
				log("awaiting packfile(s)")
				helperStdOutScanner := bufio.NewScanner(helperStdOut)
				helperStdOutScanner.Split(splitOutput)

				// TODO: fix issues with multiplexing
				for helperStdOutScanner.Scan() {
					output := helperStdOutScanner.Bytes()

					if _, err := os.Stdout.Write(output); err != nil {
						return nil, false, err
					}

					if bytes.Equal(output, endOfReadPkt) {
						if !stdInScanner.Scan() {
							break
						}
						command = stdInScanner.Bytes()
						if len(command) == 0 {
							break
						}
						// we have a second want batch
						currentState = requestingWants
						goto alreadyScanned
					}
				}
				if currentState == packfileIncoming {
					currentState = packfileDone
				}
			}
		}
		if currentState == packfileDone {
			break
		}
	}

	if err := helperStdIn.Close(); err != nil {
		return nil, false, err
	}

	if err := helperStdOut.Close(); err != nil {
		return nil, false, err
	}

	if err := helper.Wait(); err != nil {
		return nil, false, err
	}

	return gittufRefsTips, isPush, nil
}
