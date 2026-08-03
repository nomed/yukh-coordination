package gcpworkload

import (
	"context"
	"errors"
	"io"
	"math"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
)

const cloudStorageContentType = "application/octet-stream"

// CloudObjectStore is the RFC-0020 single-object, exact-generation Cloud
// Storage boundary. Construction never discovers credentials: the caller must
// supply an already authenticated client with its identity policy closed.
type CloudObjectStore struct {
	backend objectBackend
	timeout time.Duration
}

type objectBackend interface {
	load(context.Context, Generation) (objectResult, error)
	save(context.Context, Generation, []byte, CRC32C) (objectResult, error)
	delete(context.Context, Generation) error
}

type objectResult struct {
	body         []byte
	bucket       string
	object       string
	generation   int64
	checksum     uint32
	size         int64
	decompressed bool
}

type sdkObjectBackend struct {
	readHandle     *storage.ObjectHandle
	mutationHandle *storage.ObjectHandle
	bucket         string
	object         string
}

func NewCloudObjectStore(client *storage.Client, bucket, object string, timeout time.Duration, maximumAttempts int) (*CloudObjectStore, error) {
	if client == nil || !validBucket(bucket) || !validObject(object) || timeout <= 0 || maximumAttempts < 1 || maximumAttempts > 10 {
		return nil, ErrInvalidContract
	}
	base := client.Bucket(bucket).Object(object)
	readHandle := base.Retryer(
		storage.WithPolicy(storage.RetryIdempotent),
		storage.WithMaxAttempts(maximumAttempts),
	)
	mutationHandle := base.Retryer(storage.WithPolicy(storage.RetryNever))
	return newCloudObjectStore(&sdkObjectBackend{readHandle: readHandle, mutationHandle: mutationHandle, bucket: bucket, object: object}, timeout)
}

func newCloudObjectStore(backend objectBackend, timeout time.Duration) (*CloudObjectStore, error) {
	if backend == nil || timeout <= 0 {
		return nil, ErrInvalidContract
	}
	return &CloudObjectStore{backend: backend, timeout: timeout}, nil
}

func (s *CloudObjectStore) Load(ctx context.Context) (StoredObject, error) {
	if s == nil || s.backend == nil {
		return StoredObject{}, ErrInvalidContract
	}
	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	result, err := s.backend.load(operation, AbsentGeneration())
	if err != nil {
		return StoredObject{}, classifyStorageError(err, false)
	}
	if result.decompressed || result.generation <= 0 || result.size != int64(len(result.body)) || len(result.body) == 0 || len(result.body) > maximumEnvelopeBytes || Checksum(result.body).value != result.checksum {
		return StoredObject{}, ErrIntegrity
	}
	generation, err := NewGeneration(uint64(result.generation))
	if err != nil {
		return StoredObject{}, ErrIntegrity
	}
	stored, err := NewStoredObject(result.body, generation, Checksum(result.body))
	if err != nil {
		return StoredObject{}, ErrIntegrity
	}
	return stored, nil
}

// LoadGeneration verifies that the requested generation is still the live
// object without selecting a noncurrent version.
func (s *CloudObjectStore) LoadGeneration(ctx context.Context, expected Generation) (StoredObject, error) {
	value, valid := expected.ProviderValue()
	if s == nil || s.backend == nil || !valid || expected.IsAbsent() || value > math.MaxInt64 {
		return StoredObject{}, ErrInvalidContract
	}
	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	result, err := s.backend.load(operation, expected)
	if err != nil {
		return StoredObject{}, classifyStorageError(err, false)
	}
	if result.generation != int64(value) || result.decompressed || result.size != int64(len(result.body)) || len(result.body) == 0 || len(result.body) > maximumEnvelopeBytes || Checksum(result.body).value != result.checksum {
		return StoredObject{}, ErrIntegrity
	}
	stored, err := NewStoredObject(result.body, expected, Checksum(result.body))
	if err != nil {
		return StoredObject{}, ErrIntegrity
	}
	return stored, nil
}

func (s *CloudObjectStore) Save(ctx context.Context, expected Generation, body []byte, checksum CRC32C) (Generation, error) {
	if s == nil || s.backend == nil || !expected.valid() || len(body) == 0 || len(body) > maximumEnvelopeBytes || !checksum.Matches(body) {
		return Generation{}, ErrInvalidContract
	}
	if _, err := ParseEnvelope(body); err != nil {
		return Generation{}, ErrInvalidContract
	}
	if value, _ := expected.ProviderValue(); value > math.MaxInt64 {
		return Generation{}, ErrInvalidContract
	}
	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	result, err := s.backend.save(operation, expected, clone(body), checksum)
	if err != nil {
		return Generation{}, classifyStorageError(err, true)
	}
	if result.generation <= 0 || result.size != int64(len(body)) || result.checksum != checksum.ProviderValue() {
		return Generation{}, ErrIntegrity
	}
	generation, err := NewGeneration(uint64(result.generation))
	if err != nil {
		return Generation{}, ErrIntegrity
	}
	return generation, nil
}

func (s *CloudObjectStore) Delete(ctx context.Context, expected Generation) error {
	value, valid := expected.ProviderValue()
	if s == nil || s.backend == nil || !valid || expected.IsAbsent() || value > math.MaxInt64 {
		return ErrInvalidContract
	}
	operation, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return classifyStorageError(s.backend.delete(operation, expected), true)
}

func (b *sdkObjectBackend) load(ctx context.Context, expected Generation) (objectResult, error) {
	handle := b.readHandle.ReadCompressed(true)
	if !expected.IsAbsent() {
		value, _ := expected.ProviderValue()
		handle = handle.If(storage.Conditions{GenerationMatch: int64(value)})
	}
	reader, err := handle.NewReader(ctx)
	if err != nil {
		return objectResult{}, err
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, maximumEnvelopeBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		return objectResult{}, readErr
	}
	if closeErr != nil {
		return objectResult{}, closeErr
	}
	return objectResult{body: body, bucket: b.bucket, object: b.object, generation: reader.Attrs.Generation, checksum: reader.Attrs.CRC32C, size: reader.Attrs.Size, decompressed: reader.Attrs.Decompressed}, nil
}

func (b *sdkObjectBackend) save(ctx context.Context, expected Generation, body []byte, checksum CRC32C) (objectResult, error) {
	value, _ := expected.ProviderValue()
	conditions := storage.Conditions{DoesNotExist: expected.IsAbsent()}
	if !expected.IsAbsent() {
		conditions.GenerationMatch = int64(value)
	}
	writer := b.mutationHandle.If(conditions).NewWriter(ctx)
	writer.ChunkSize = 0
	writer.ContentType = cloudStorageContentType
	writer.CRC32C = checksum.ProviderValue()
	writer.SendCRC32C = true
	if written, err := writer.Write(body); err != nil || written != len(body) {
		_ = writer.Close()
		if err != nil {
			return objectResult{}, err
		}
		return objectResult{}, io.ErrShortWrite
	}
	if err := writer.Close(); err != nil {
		return objectResult{}, err
	}
	attrs := writer.Attrs()
	if attrs == nil || attrs.Bucket != b.bucket || attrs.Name != b.object {
		return objectResult{}, ErrIntegrity
	}
	return objectResult{bucket: attrs.Bucket, object: attrs.Name, generation: attrs.Generation, checksum: attrs.CRC32C, size: attrs.Size}, nil
}

func (b *sdkObjectBackend) delete(ctx context.Context, expected Generation) error {
	value, _ := expected.ProviderValue()
	return b.mutationHandle.If(storage.Conditions{GenerationMatch: int64(value)}).Delete(ctx)
}

func classifyStorageError(err error, outcomeMayBeAmbiguous bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrObjectNotExist) {
		return ErrAbsent
	}
	var apiError *googleapi.Error
	if errors.As(err, &apiError) {
		switch apiError.Code {
		case 404:
			return ErrAbsent
		case 412:
			return ErrConflict
		default:
			if outcomeMayBeAmbiguous && (apiError.Code == 408 || apiError.Code == 429 || apiError.Code >= 500) {
				return ErrAmbiguous
			}
			return ErrUnavailable
		}
	}
	if outcomeMayBeAmbiguous {
		return ErrAmbiguous
	}
	return ErrUnavailable
}
