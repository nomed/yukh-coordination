package primitiveslauncher

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrInvalid = errors.New("invalid descriptor launcher input")

const (
	serviceExecutable   = "/usr/local/bin/yukh-coordination-primitives"
	bootstrapExecutable = "/usr/local/bin/yukh-coordination-primitives-bootstrap"
	maxSecretBytes      = 64 * 1024
)

type Process struct {
	executable string
	arguments  []string
	secrets    []*os.File
	targets    []int
}

func Prepare(arguments []string) (*Process, error) {
	if len(arguments) < 1 {
		return nil, ErrInvalid
	}
	var executable string
	var targets []int
	switch arguments[0] {
	case "service":
		if len(arguments) != 4 {
			return nil, ErrInvalid
		}
		executable = serviceExecutable
		targets = []int{3, 4}
	case "bootstrap":
		if len(arguments) != 3 {
			return nil, ErrInvalid
		}
		executable = bootstrapExecutable
		targets = []int{3}
	default:
		return nil, ErrInvalid
	}
	config := arguments[1]
	if !exactAbsolute(config) {
		return nil, ErrInvalid
	}
	seen := map[string]struct{}{config: {}}
	secrets := make([]*os.File, 0, len(targets))
	for _, path := range arguments[2:] {
		if !exactAbsolute(path) {
			closeFiles(secrets)
			return nil, ErrInvalid
		}
		if _, exists := seen[path]; exists {
			closeFiles(secrets)
			return nil, ErrInvalid
		}
		seen[path] = struct{}{}
		secret, err := openSecret(path)
		if err != nil {
			closeFiles(secrets)
			return nil, ErrInvalid
		}
		secrets = append(secrets, secret)
	}
	return &Process{
		executable: executable,
		arguments:  []string{executable, config},
		secrets:    secrets,
		targets:    targets,
	}, nil
}

func exactAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func openSecret(path string) (*os.File, error) {
	var before unix.Stat_t
	if unix.Lstat(path, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&0o022 != 0 || before.Size < 1 || before.Size > maxSecretBytes {
		return nil, ErrInvalid
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	var after unix.Stat_t
	if unix.Fstat(descriptor, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino ||
		before.Mode != after.Mode || before.Size != after.Size {
		_ = unix.Close(descriptor)
		return nil, ErrInvalid
	}
	return os.NewFile(uintptr(descriptor), "redacted-secret"), nil
}

func (process *Process) Close() {
	if process == nil {
		return
	}
	closeFiles(process.secrets)
	process.secrets = nil
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (process *Process) Exec() error {
	if process == nil || len(process.secrets) != len(process.targets) {
		return ErrInvalid
	}
	temporary := make([]int, 0, len(process.secrets))
	for _, secret := range process.secrets {
		if secret == nil {
			closeDescriptors(temporary)
			return ErrInvalid
		}
		descriptor, err := unix.FcntlInt(secret.Fd(), unix.F_DUPFD_CLOEXEC, 10)
		if err != nil {
			closeDescriptors(temporary)
			return ErrInvalid
		}
		temporary = append(temporary, descriptor)
	}
	for index, descriptor := range temporary {
		if unix.Dup3(descriptor, process.targets[index], 0) != nil {
			closeDescriptors(temporary)
			return ErrInvalid
		}
	}
	process.Close()
	closeDescriptors(temporary)
	if unix.CloseRange(5, ^uint(0), unix.CLOSE_RANGE_UNSHARE) != nil {
		return ErrInvalid
	}
	return syscall.Exec(process.executable, process.arguments, []string{})
}

func closeDescriptors(descriptors []int) {
	for _, descriptor := range descriptors {
		_ = unix.Close(descriptor)
	}
}
