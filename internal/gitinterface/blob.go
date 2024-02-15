// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"errors"

	"github.com/gittuf/gittuf/internal/gitinterface/gogit"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

var ErrWrittenBlobLengthMismatch = errors.New("length of blob written does not match length of contents")

// ReadBlob returns the contents of a the blob referenced by blobID.
func ReadBlob(repo *git.Repository, blobID plumbing.Hash) ([]byte, error) {
	client := gogit.NewGoGitClientForRepository(repo)
	return client.ReadBlob(blobID)
}

// WriteBlob creates a blob object with the specified contents and returns the
// ID of the resultant blob.
func WriteBlob(repo *git.Repository, contents []byte) (plumbing.Hash, error) {
	client := gogit.NewGoGitClientForRepository(repo)
	return client.WriteBlob(contents)
}

// GetBlob returns the requested blob object.
func GetBlob(repo *git.Repository, blobID plumbing.Hash) (*object.Blob, error) {
	client := gogit.NewGoGitClientForRepository(repo)
	return client.GetBlob(blobID)
}

// EmptyBlob returns the hash of an empty blob in a Git repository.
// Note: it is generated on the fly rather than stored as a constant to support
// SHA-256 repositories in future.
func EmptyBlob() plumbing.Hash {
	obj := memory.NewStorage().NewEncodedObject()
	obj.SetType(plumbing.BlobObject)

	return obj.Hash()
}
