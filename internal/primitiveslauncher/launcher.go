package primitiveslauncher

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/nomed/yukh-coordination/internal/primitivesstaging"
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
	case "service-kubernetes":
		if len(arguments) != 6 {
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
	secretPaths := arguments[2:]
	seen := make(map[string]struct{})
	if arguments[0] == "service-kubernetes" {
		template, podIP, output := arguments[1], arguments[2], arguments[3]
		if !exactAbsolute(template) || !exactAbsolute(podIP) || !exactAbsolute(output) || template == podIP || template == output || podIP == output || renderKubernetesConfig(template, podIP, output) != nil {
			return nil, ErrInvalid
		}
		config = output
		secretPaths = arguments[4:]
		seen[template], seen[podIP], seen[output] = struct{}{}, struct{}{}, struct{}{}
	}
	if !exactAbsolute(config) {
		return nil, ErrInvalid
	}
	seen[config] = struct{}{}
	secrets := make([]*os.File, 0, len(targets))
	for _, path := range secretPaths {
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

func renderKubernetesConfig(templatePath, podIPPath, outputPath string) error {
	template, err := readCheckedFile(templatePath, maxSecretBytes)
	if err != nil {
		return ErrInvalid
	}
	podIP, err := readCheckedFile(podIPPath, 64)
	if err != nil {
		return ErrInvalid
	}
	rendered, err := primitivesstaging.RenderPodIPConfig(template, podIP)
	if err != nil {
		return ErrInvalid
	}
	if existing, err := readCheckedFile(outputPath, maxSecretBytes); err == nil {
		if bytes.Equal(existing, rendered) {
			return nil
		}
		return ErrInvalid
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrInvalid
	}
	parent := filepath.Dir(outputPath)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalid
	}
	temporary, err := os.CreateTemp(parent, ".yukh-rendered-config-*")
	if err != nil {
		return ErrInvalid
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if temporary.Chmod(0o400) != nil {
		return ErrInvalid
	}
	if written, err := temporary.Write(rendered); err != nil || written != len(rendered) || temporary.Sync() != nil || temporary.Close() != nil || os.Rename(temporaryPath, outputPath) != nil {
		return ErrInvalid
	}
	ok = true
	return nil
}

func readCheckedFile(path string, limit int64) ([]byte, error) {
	if !exactAbsolute(path) {
		return nil, ErrInvalid
	}
	file, err := openSecret(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, ErrInvalid
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(value) == 0 || int64(len(value)) > limit {
		return nil, ErrInvalid
	}
	return value, nil
}

func exactAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func openSecret(path string) (*os.File, error) {
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG ||
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
