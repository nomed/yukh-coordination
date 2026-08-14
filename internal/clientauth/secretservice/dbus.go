package secretservice

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/nomed/yukh-coordination/internal/clientauth/workstation"
)

const (
	secretServicePath   = dbus.ObjectPath("/org/freedesktop/secrets")
	serviceInterface    = "org.freedesktop.Secret.Service"
	collectionInterface = "org.freedesktop.Secret.Collection"
	itemInterface       = "org.freedesktop.Secret.Item"
	propertiesInterface = "org.freedesktop.DBus.Properties"
	sessionInterface    = "org.freedesktop.Secret.Session"
	dhAlgorithm         = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
	gnomeSecretType     = "text/plain"
)

var (
	dhGenerator = big.NewInt(2)
	dhPrime, _  = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD"+
			"129024E088A67CC74020BBEA63B139B22514A08798E3404D"+
			"DEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
			"FFFFFFFFFFFFFFFF", 16)
)

type dbusService struct {
	conn    *dbus.Conn
	binding workstation.SecretServiceBinding
}

func openDBusService(ctx context.Context, binding workstation.SecretServiceBinding, bus *os.File) (rootService, error) {
	if ctx == nil || bus == nil {
		return nil, errUnavailable
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !deadline.After(time.Now()) {
		return nil, errUnavailable
	}
	transport, err := net.FileConn(bus)
	if err != nil {
		return nil, errUnavailable
	}
	if err := transport.SetDeadline(deadline); err != nil {
		_ = transport.Close()
		return nil, errUnavailable
	}
	defer transport.SetDeadline(time.Time{})

	conn, err := dbus.NewConn(transport)
	if err != nil {
		_ = transport.Close()
		return nil, errUnavailable
	}
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Geteuid()))}); err != nil {
		_ = conn.Close()
		return nil, errUnavailable
	}
	if err := conn.Hello(); err != nil {
		_ = conn.Close()
		return nil, errUnavailable
	}
	if err := bus.Close(); err != nil {
		_ = conn.Close()
		return nil, errUnavailable
	}
	return &dbusService{conn: conn, binding: binding}, nil
}

func (s *dbusService) Close() error {
	if s == nil || s.conn == nil {
		return errUnavailable
	}
	if err := s.conn.Close(); err != nil {
		return errUnavailable
	}
	return nil
}

func (s *dbusService) OpenSession(ctx context.Context) (rootSession, error) {
	if s == nil || s.conn == nil || ctx == nil || ctx.Err() != nil {
		return nil, errUnavailable
	}
	private, public, err := dhKeypair()
	if err != nil {
		return nil, errUnavailable
	}
	defer private.SetInt64(0)
	var output dbus.Variant
	var path dbus.ObjectPath
	call := s.object(secretServicePath).CallWithContext(
		ctx, serviceInterface+".OpenSession", dbus.FlagNoAutoStart, dhAlgorithm, dbus.MakeVariant(public.Bytes()),
	)
	if call.Err != nil || call.Store(&output, &path) != nil || !path.IsValid() || path == "/" {
		return nil, errUnavailable
	}
	serverPublic, ok := output.Value().([]byte)
	if !ok {
		return nil, errUnavailable
	}
	defer clear(serverPublic)
	key, err := deriveSessionKey(private, serverPublic)
	if err != nil {
		return nil, errUnavailable
	}
	return &dbusSession{service: s, path: path, key: key}, nil
}

func (s *dbusService) CollectionItems(ctx context.Context) (bool, []string, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return false, nil, errUnavailable
	}
	collection := s.object(dbus.ObjectPath(s.binding.Collection()))
	lockedValue, err := getProperty(ctx, collection, collectionInterface, "Locked")
	if err != nil {
		return false, nil, errUnavailable
	}
	locked, ok := lockedValue.Value().(bool)
	if !ok {
		return false, nil, errUnavailable
	}
	itemsValue, err := getProperty(ctx, collection, collectionInterface, "Items")
	if err != nil {
		return false, nil, errUnavailable
	}
	items, ok := itemsValue.Value().([]dbus.ObjectPath)
	if !ok || len(items) > maximumCollectionItems {
		return false, nil, errUnavailable
	}
	paths := make([]string, len(items))
	for index, path := range items {
		if !path.IsValid() || path == "/" {
			return false, nil, errUnavailable
		}
		paths[index] = string(path)
	}
	return locked, paths, nil
}

func (s *dbusService) ItemMetadata(ctx context.Context, path string) (itemMetadata, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !validPath(path) {
		return itemMetadata{}, errUnavailable
	}
	var properties map[string]dbus.Variant
	call := s.object(dbus.ObjectPath(path)).CallWithContext(ctx, propertiesInterface+".GetAll", dbus.FlagNoAutoStart, itemInterface)
	if call.Err != nil || call.Store(&properties) != nil {
		return itemMetadata{}, errUnavailable
	}
	locked, lockedOK := properties["Locked"].Value().(bool)
	attributes, attributesOK := properties["Attributes"].Value().(map[string]string)
	contentType, typeOK := properties["Type"].Value().(string)
	label, labelOK := properties["Label"].Value().(string)
	if !lockedOK || !attributesOK || !typeOK || !labelOK || len(attributes) > 8 {
		return itemMetadata{}, errUnavailable
	}
	copyAttributes := make(map[string]string, len(attributes))
	for name, value := range attributes {
		if name == "" || value == "" || len(name) > 256 || len(value) > 256 {
			return itemMetadata{}, errUnavailable
		}
		copyAttributes[name] = value
	}
	return itemMetadata{path: path, locked: locked, attributes: copyAttributes, contentType: contentType, label: label}, nil
}

func (s *dbusService) ItemSecret(ctx context.Context, session rootSession, path string) ([]byte, string, error) {
	current, ok := session.(*dbusSession)
	if s == nil || !ok || current.service != s || ctx == nil || ctx.Err() != nil || !validPath(path) {
		return nil, "", errUnavailable
	}
	var secret dbusSecret
	call := s.object(dbus.ObjectPath(path)).CallWithContext(ctx, itemInterface+".GetSecret", dbus.FlagNoAutoStart, current.path)
	if call.Err != nil || call.Store(&secret) != nil || secret.Session != current.path ||
		(secret.ContentType != rootContentType && secret.ContentType != gnomeSecretType) {
		clear(secret.Parameters)
		clear(secret.Value)
		return nil, "", errUnavailable
	}
	plaintext, err := current.decrypt(secret.Parameters, secret.Value)
	clear(secret.Parameters)
	clear(secret.Value)
	if err != nil {
		clear(plaintext)
		return nil, "", errUnavailable
	}
	// GNOME Keyring normalizes Secret.ContentType to text/plain. The exact
	// persisted type remains verified through the Item.Type property.
	return plaintext, rootContentType, nil
}

func (s *dbusService) CreateItem(ctx context.Context, session rootSession, item rootItem) (string, bool, bool, error) {
	current, ok := session.(*dbusSession)
	if s == nil || !ok || current.service != s || ctx == nil || ctx.Err() != nil ||
		!equalAttributes(item.attributes, rootAttributes(s.binding, item.attributes[rootProfileAttribute])) ||
		item.contentType != rootContentType || item.label != rootLabel || isZero(item.value[:]) {
		return "", false, false, errUnavailable
	}
	parameters, value, err := current.encrypt(item.value[:])
	if err != nil {
		return "", false, false, errUnavailable
	}
	defer clear(parameters)
	defer clear(value)
	var path, prompt dbus.ObjectPath
	call := s.object(dbus.ObjectPath(s.binding.Collection())).CallWithContext(
		ctx, collectionInterface+".CreateItem", dbus.FlagNoAutoStart,
		map[string]dbus.Variant{
			itemInterface + ".Label":      dbus.MakeVariant(item.label),
			itemInterface + ".Attributes": dbus.MakeVariant(item.attributes),
			itemInterface + ".Type":       dbus.MakeVariant(item.contentType),
		},
		dbusSecret{Session: current.path, Parameters: parameters, Value: value, ContentType: rootContentType},
		false,
	)
	if call.Err != nil {
		return "", false, ambiguousCreate(call.Err), errUnavailable
	}
	if call.Store(&path, &prompt) != nil || !path.IsValid() || !prompt.IsValid() {
		return "", false, true, errUnavailable
	}
	return string(path), prompt != "/", false, nil
}

func (s *dbusService) object(path dbus.ObjectPath) dbus.BusObject {
	return s.conn.Object(s.binding.Name(), path)
}

type dbusSession struct {
	service *dbusService
	path    dbus.ObjectPath
	key     []byte
	once    sync.Once
	err     error
}

func (s *dbusSession) Close(ctx context.Context) error {
	if s == nil || s.service == nil || s.service.conn == nil || !s.path.IsValid() || s.path == "/" {
		return errUnavailable
	}
	s.once.Do(func() {
		call := s.service.object(s.path).CallWithContext(ctx, sessionInterface+".Close", dbus.FlagNoAutoStart)
		if call.Err != nil {
			s.err = errUnavailable
		}
		clear(s.key)
		s.key = nil
	})
	return s.err
}

func (s *dbusSession) encrypt(plaintext []byte) ([]byte, []byte, error) {
	if s == nil || len(s.key) != aes.BlockSize || len(plaintext) != 32 {
		return nil, nil, errUnavailable
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, nil, errUnavailable
	}
	padded := make([]byte, len(plaintext)+aes.BlockSize)
	copy(padded, plaintext)
	for index := len(plaintext); index < len(padded); index++ {
		padded[index] = aes.BlockSize
	}
	defer clear(padded)
	parameters := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, parameters); err != nil {
		clear(parameters)
		return nil, nil, errUnavailable
	}
	value := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, parameters).CryptBlocks(value, padded)
	return parameters, value, nil
}

func (s *dbusSession) decrypt(parameters, value []byte) ([]byte, error) {
	if s == nil || len(s.key) != aes.BlockSize || len(parameters) != aes.BlockSize ||
		len(value) == 0 || len(value) > 64 || len(value)%aes.BlockSize != 0 {
		return nil, errUnavailable
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, errUnavailable
	}
	padded := make([]byte, len(value))
	defer clear(padded)
	cipher.NewCBCDecrypter(block, parameters).CryptBlocks(padded, value)
	padding := int(padded[len(padded)-1])
	if padding == 0 || padding > aes.BlockSize || padding >= len(padded) {
		return nil, errUnavailable
	}
	for _, item := range padded[len(padded)-padding:] {
		if int(item) != padding {
			return nil, errUnavailable
		}
	}
	plaintext := append([]byte(nil), padded[:len(padded)-padding]...)
	return plaintext, nil
}

type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func getProperty(ctx context.Context, object dbus.BusObject, iface, name string) (dbus.Variant, error) {
	var value dbus.Variant
	call := object.CallWithContext(ctx, propertiesInterface+".Get", dbus.FlagNoAutoStart, iface, name)
	if call.Err != nil || call.Store(&value) != nil {
		return dbus.Variant{}, errUnavailable
	}
	return value, nil
}

func dhKeypair() (*big.Int, *big.Int, error) {
	upper := new(big.Int).Sub(dhPrime, big.NewInt(1))
	private, err := rand.Int(rand.Reader, upper)
	if err != nil || private.Sign() == 0 {
		return nil, nil, errUnavailable
	}
	return private, new(big.Int).Exp(dhGenerator, private, dhPrime), nil
}

func deriveSessionKey(private *big.Int, encodedPublic []byte) ([]byte, error) {
	if private == nil || private.Sign() <= 0 || len(encodedPublic) == 0 || len(encodedPublic) > 128 {
		return nil, errUnavailable
	}
	peer := new(big.Int).SetBytes(encodedPublic)
	upper := new(big.Int).Sub(dhPrime, big.NewInt(1))
	if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(upper) >= 0 {
		return nil, errUnavailable
	}
	shared := new(big.Int).Exp(peer, private, dhPrime)
	defer shared.SetInt64(0)
	key, err := hkdf.Key(sha256.New, shared.Bytes(), nil, "", aes.BlockSize)
	if err != nil {
		return nil, errUnavailable
	}
	return key, nil
}

func ambiguousCreate(err error) bool {
	if err == nil {
		return false
	}
	switch err.(type) {
	case dbus.Error, *dbus.Error:
		return false
	default:
		return true
	}
}
