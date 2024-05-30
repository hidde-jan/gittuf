// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/gittuf/gittuf/internal/common"
	"github.com/gittuf/gittuf/internal/dev"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/rsl"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/assert"
)

func TestVerifyRef(t *testing.T) {
	repo := createTestRepositoryWithPolicy(t, "")

	refName := "refs/heads/main"
	remoteRefName := "refs/heads/not-main"

	if err := repo.r.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName(refName), plumbing.ZeroHash)); err != nil {
		t.Fatal(err)
	}

	commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo.r, refName, 1, gpgKeyBytes)
	entry := rsl.NewReferenceEntry(refName, commitIDs[0])
	entryID := common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgKeyBytes)
	entry.ID = entryID

	// Add one entry for a different remote ref name
	entry = rsl.NewReferenceEntry(remoteRefName, commitIDs[0])
	entryID = common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgKeyBytes)
	entry.ID = entryID

	tests := map[string]struct {
		localRefName  string
		remoteRefName string
		latestOnly    bool
		err           error
	}{
		"absolute ref, not full": {
			localRefName: refName,
			latestOnly:   true,
		},
		"absolute ref, full": {
			localRefName: refName,
			latestOnly:   false,
		},
		"relative ref, not full": {
			localRefName: "main",
			latestOnly:   true,
		},
		"relative ref, full": {
			localRefName: "main",
			latestOnly:   false,
		},
		"unknown ref, full": {
			localRefName: "refs/heads/unknown",
			latestOnly:   false,
			err:          rsl.ErrRSLEntryNotFound,
		},
		"different local and remote ref names, not full": {
			localRefName:  refName,
			remoteRefName: refName,
			latestOnly:    true,
		},
		"different local and remote ref names, full": {
			localRefName:  refName,
			remoteRefName: refName,
			latestOnly:    false,
		},
	}

	for name, test := range tests {
		err := repo.VerifyRef(context.Background(), test.localRefName, test.remoteRefName, test.latestOnly)
		if test.err != nil {
			assert.ErrorIs(t, err, test.err, fmt.Sprintf("unexpected error in test '%s'", name))
		} else {
			assert.Nil(t, err, fmt.Sprintf("unexpected error in test '%s'", name))
		}
	}

	// Add another commit
	common.AddNTestCommitsToSpecifiedRef(t, repo.r, refName, 1, gpgKeyBytes)
	err := repo.VerifyRef(context.Background(), refName, "", true)
	assert.ErrorIs(t, err, ErrRefStateDoesNotMatchRSL)
	err = repo.VerifyRef(context.Background(), refName, "", false)
	assert.ErrorIs(t, err, ErrRefStateDoesNotMatchRSL)
}

func TestVerifyRefFromEntry(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	repo := createTestRepositoryWithPolicy(t, "")

	refName := "refs/heads/main"
	remoteRefName := "refs/heads/not-main"
	if err := repo.r.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName(refName), plumbing.ZeroHash)); err != nil {
		t.Fatal(err)
	}

	// Policy violation
	commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo.r, refName, 1, gpgUnauthorizedKeyBytes)
	// Violation for refName
	entry := rsl.NewReferenceEntry(refName, commitIDs[0])
	violatingEntryID := common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgUnauthorizedKeyBytes)
	// Violation for remoteRefName
	entry = rsl.NewReferenceEntry(remoteRefName, commitIDs[0])
	violatingRemoteRefNameEntryID := common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgUnauthorizedKeyBytes)

	// No policy violation for refName
	commitIDs = common.AddNTestCommitsToSpecifiedRef(t, repo.r, refName, 1, gpgKeyBytes)
	// refName
	entry = rsl.NewReferenceEntry(refName, commitIDs[0])
	goodEntryID := common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgKeyBytes)
	// remoteRefName
	entry = rsl.NewReferenceEntry(remoteRefName, commitIDs[0])
	goodRemoteRefNameEntryID := common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgKeyBytes)

	// No policy violation for refName (what we verify)
	commitIDs = common.AddNTestCommitsToSpecifiedRef(t, repo.r, refName, 1, gpgKeyBytes)
	entry = rsl.NewReferenceEntry(refName, commitIDs[0])
	common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgKeyBytes)
	// No policy violation for remoteRefName (what we verify)
	entry = rsl.NewReferenceEntry(remoteRefName, commitIDs[0])
	common.CreateTestRSLReferenceEntryCommit(t, repo.r, entry, gpgKeyBytes)

	tests := map[string]struct {
		localRefName  string
		remoteRefName string
		fromEntryID   plumbing.Hash
		err           error
	}{
		"absolute ref, from non-violating": {
			localRefName: "refs/heads/main",
			fromEntryID:  goodEntryID,
		},
		"absolute ref, from violating": {
			localRefName: "refs/heads/main",
			fromEntryID:  violatingEntryID,
			err:          policy.ErrUnauthorizedSignature,
		},
		"relative ref, from non-violating": {
			localRefName: "main",
			fromEntryID:  goodEntryID,
		},
		"relative ref, from violating": {
			localRefName: "main",
			fromEntryID:  violatingEntryID,
			err:          policy.ErrUnauthorizedSignature,
		},
		"unknown ref": {
			localRefName: "refs/heads/unknown",
			err:          rsl.ErrRSLEntryNotFound,
		},
		"different local and remote ref names, from non-violating": {
			localRefName:  refName,
			remoteRefName: remoteRefName,
			fromEntryID:   goodRemoteRefNameEntryID,
		},
		"different local and remote ref names, from violating": {
			localRefName:  refName,
			remoteRefName: remoteRefName,
			fromEntryID:   violatingRemoteRefNameEntryID,
		},
	}

	for name, test := range tests {
		err := repo.VerifyRefFromEntry(testCtx, test.localRefName, test.remoteRefName, test.fromEntryID.String())
		if test.err != nil {
			assert.ErrorIs(t, err, test.err, fmt.Sprintf("unexpected error in test '%s'", name))
		} else {
			assert.Nil(t, err, fmt.Sprintf("unexpected error in test '%s'", name))
		}
	}

	// Add another commit
	common.AddNTestCommitsToSpecifiedRef(t, repo.r, refName, 1, gpgKeyBytes)

	// Verifying from only good entry tells us ref does not match RSL
	err := repo.VerifyRefFromEntry(testCtx, refName, "", goodEntryID.String())
	assert.ErrorIs(t, err, ErrRefStateDoesNotMatchRSL)

	// Verifying from violating entry tells us unauthorized signature
	err = repo.VerifyRefFromEntry(testCtx, refName, "", violatingEntryID.String())
	assert.ErrorIs(t, err, policy.ErrUnauthorizedSignature)
}
