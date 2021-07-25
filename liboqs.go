// Copyright 2019 Thales UK Limited
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Package goliboqs is a Go wrapper around the liboqs library
// (see https://github.com/open-quantum-safe/liboqs).
//
// Usage
//
// Sample usage is shown below. Error handling omitted for brevity.
//
//   // Load the library (don't forget to close)
//   lib, _ := goliboqs.LoadLib("/path/to/liboqs.so")
//   defer lib.Close()
//
//   // Get a particular KEM (don't forget to close)
//   kem, _ := lib.GetKem(goliboqs.KemKyber1024)
//   defer kem.Close()
//
//   // Use the kem...
//   publicKey, secretKey, _ := kem.KeyPair()
//   sharedSecret, ciphertext, _ := kem.Encaps(publicKey)
//   recoveredSecret, _ := kem.Decaps(ciphertext, secretKey)
//   // sharedSecret == recoveredSecret
package goliboqs

/*
#cgo CFLAGS: -Iinclude
#cgo LDFLAGS: -ldl

typedef enum {
	ERR_OK,
	ERR_CANNOT_LOAD_LIB,
	ERR_CONTEXT_CLOSED,
	ERR_MEM,
	ERR_NO_FUNCTION,
	ERR_OPERATION_FAILED,
} libResult;

#include <oqs/oqs.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
  void *handle;
} ctx;

char *errorString(libResult r) {
	switch (r) {
	case ERR_CANNOT_LOAD_LIB:
		return "cannot load library";
	case ERR_CONTEXT_CLOSED:
		return "library closed";
	case ERR_MEM:
		return "out of memory";
	case ERR_NO_FUNCTION:
		return "library missing required function";
	case ERR_OPERATION_FAILED:
		// We have no further info to share
		return "operation failed";
	default:
		return "unknown error";
	}
}

libResult New(const char *path, ctx **c) {
	*c = malloc(sizeof(ctx));
	if (!(*c)) {
		return ERR_MEM;
	}

	(*c)->handle = dlopen(path, RTLD_NOW);
	if (NULL == (*c)->handle) {
		free(*c);
		return ERR_CANNOT_LOAD_LIB;
	}

	return ERR_OK;
}

libResult GetKem(const ctx *ctx, const char *name, OQS_KEM **kem) {
	if (!ctx->handle) {
		return ERR_CONTEXT_CLOSED;
	}

	// func matches signature of OQS_KEM_new
	OQS_KEM *(*func)(const char *);
	*(void **)(&func) = dlsym(ctx->handle, "OQS_KEM_new");

	if (NULL == func) {
		return ERR_NO_FUNCTION;
	}

	*kem = (*func)(name);
	return ERR_OK;
}

libResult FreeKem(ctx *ctx, OQS_KEM *kem) {
	if (!ctx->handle) {
		return ERR_CONTEXT_CLOSED;
	}

	// func matches signature of OQS_KEM_free
	void (*func)(OQS_KEM*);
	*(void **)(&func) = dlsym(ctx->handle, "OQS_KEM_free");

	if (NULL == func) {
		return ERR_NO_FUNCTION;
	}

	(*func)(kem);
	return ERR_OK;
}

libResult Close(ctx *ctx) {
	if (!ctx->handle) {
		return ERR_CONTEXT_CLOSED;
	}

	dlclose(ctx->handle);
	ctx->handle = NULL;
	return ERR_OK;
}

libResult KeyPair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key) {
	OQS_STATUS status = kem->keypair(public_key, secret_key);
	if (status != OQS_SUCCESS) {
		return ERR_OPERATION_FAILED;
	}

	return ERR_OK;
}

libResult Encaps(const OQS_KEM *kem, const uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret) {
	OQS_STATUS status = kem->encaps(ciphertext, shared_secret, public_key);
	if (status != OQS_SUCCESS) {
		return ERR_OPERATION_FAILED;
	}
	return ERR_OK;
}

libResult Decaps(const OQS_KEM *kem, const unsigned char *ciphertext, const uint8_t *secret_key, uint8_t *shared_secret) {
	OQS_STATUS status = kem->decaps(shared_secret, ciphertext, secret_key);
	if (status != OQS_SUCCESS) {
		return ERR_OPERATION_FAILED;
	}
	return ERR_OK;
}

*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
)

// A KemType identifies a KEM algorithm. Since these are just strings, you can call
// GetKem with anything you want. This may be useful if you are using a newer version of
// liboqs.
type KemType string

// KEM types defined by liboqs (see kem.h)
// [UPDATE] - Includes all supported OQS KEMs as of 07/2021 - Modifications to liboqs-supported KEM names/identifiers should be reflected here manually
const (
	// BIKE KEM
	OQS_KEM_alg_bike_l1 KemType = "BIKE1-L1"
	OQS_KEM_alg_bike_l3 KemType = "BIKE1-L3"

	// Classic-McEliece KEM
	OQS_KEM_alg_classic_mceliece_348864   KemType = "Classic-McEliece-348864"
	OQS_KEM_alg_classic_mceliece_348864f  KemType = "Classic-McEliece-348864f"
	OQS_KEM_alg_classic_mceliece_460896   KemType = "Classic-McEliece-460896"
	OQS_KEM_alg_classic_mceliece_460896f  KemType = "Classic-McEliece-460896f"
	OQS_KEM_alg_classic_mceliece_6688128  KemType = "Classic-McEliece-6688128"
	OQS_KEM_alg_classic_mceliece_6688128f KemType = "Classic-McEliece-6688128f"
	OQS_KEM_alg_classic_mceliece_6960119  KemType = "Classic-McEliece-6960119"
	OQS_KEM_alg_classic_mceliece_6960119f KemType = "Classic-McEliece-6960119f"
	OQS_KEM_alg_classic_mceliece_8192128  KemType = "Classic-McEliece-8192128"
	OQS_KEM_alg_classic_mceliece_8192128f KemType = "Classic-McEliece-8192128f"

	// Hamming Quasi-Cyclic (HQC) KEM
	OQS_KEM_alg_hqc_128 KemType = "HQC-128"
	OQS_KEM_alg_hqc_192 KemType = "HQC-192"
	OQS_KEM_alg_hqc_256 KemType = "HQC-256"

	// Kyber KEM
	OQS_KEM_alg_kyber_512      KemType = "Kyber512"
	OQS_KEM_alg_kyber_768      KemType = "Kyber768"
	OQS_KEM_alg_kyber_1024     KemType = "Kyber1024"
	OQS_KEM_alg_kyber_512_90s  KemType = "Kyber512-90s"
	OQS_KEM_alg_kyber_768_90s  KemType = "Kyber768-90s"
	OQS_KEM_alg_kyber_1024_90s KemType = "Kyber1024-90s"

	// NTRU KEM
	OQS_KEM_alg_ntru_hps2048509      KemType = "NTRU-HPS-2048-509"
	OQS_KEM_alg_ntru_hps2048677      KemType = "NTRU-HPS-2048-677"
	OQS_KEM_alg_ntru_hps4096821      KemType = "NTRU-HPS-4096-821"
	OQS_KEM_alg_ntru_hrss701         KemType = "NTRU-HRSS-701"
	OQS_KEM_alg_ntruprime_ntrulpr653 KemType = "ntrulpr653"
	OQS_KEM_alg_ntruprime_ntrulpr761 KemType = "ntrulpr761"
	OQS_KEM_alg_ntruprime_ntrulpr857 KemType = "ntrulpr857"
	OQS_KEM_alg_ntruprime_sntrup653  KemType = "sntrup653"
	OQS_KEM_alg_ntruprime_sntrup761  KemType = "sntrup761"
	OQS_KEM_alg_ntruprime_sntrup857  KemType = "sntrup857"

	// Saber KEM
	OQS_KEM_alg_saber_lightsaber KemType = "LightSaber-KEM"
	OQS_KEM_alg_saber_saber      KemType = "Saber-KEM"
	OQS_KEM_alg_saber_firesaber  KemType = "FireSaber-KEM"

	// Frodo KEM
	OQS_KEM_alg_frodokem_640_aes    KemType = "FrodoKEM-640-AES"
	OQS_KEM_alg_frodokem_640_shake  KemType = "FrodoKEM-640-SHAKE"
	OQS_KEM_alg_frodokem_976_aes    KemType = "FrodoKEM-976-AES"
	OQS_KEM_alg_frodokem_976_shake  KemType = "FrodoKEM-976-SHAKE"
	OQS_KEM_alg_frodokem_1344_aes   KemType = "FrodoKEM-1344-AES"
	OQS_KEM_alg_frodokem_1344_shake KemType = "FrodoKEM-1344-SHAKE"

	// SIDH KEM
	OQS_KEM_alg_sidh_p434            KemType = "SIDH-p434"
	OQS_KEM_alg_sidh_p434_compressed KemType = "SIDH-p434-compressed"
	OQS_KEM_alg_sidh_p503            KemType = "SIDH-p503"
	OQS_KEM_alg_sidh_p503_compressed KemType = "SIDH-p503-compressed"
	OQS_KEM_alg_sidh_p610            KemType = "SIDH-p610"
	OQS_KEM_alg_sidh_p610_compressed KemType = "SIDH-p610-compressed"
	OQS_KEM_alg_sidh_p751            KemType = "SIDH-p751"
	OQS_KEM_alg_sidh_p751_compressed KemType = "SIDH-p751-compressed"

	// SIKE KEM
	OQS_KEM_alg_sike_p434            KemType = "SIKE-p434"
	OQS_KEM_alg_sike_p434_compressed KemType = "SIKE-p434-compressed"
	OQS_KEM_alg_sike_p503            KemType = "SIKE-p503"
	OQS_KEM_alg_sike_p503_compressed KemType = "SIKE-p503-compressed"
	OQS_KEM_alg_sike_p610            KemType = "SIKE-p610"
	OQS_KEM_alg_sike_p610_compressed KemType = "SIKE-p610-compressed"
	OQS_KEM_alg_sike_p751            KemType = "SIKE-p751"
	OQS_KEM_alg_sike_p751_compressed KemType = "SIKE-p751-compressed"
)

var errAlreadyClosed = errors.New("already closed")
var errAlgDisabledOrUnknown = errors.New("KEM algorithm is unknown or disabled")

// operationFailed exposed to help test code (which cannot use cgo "C.<foo>" variables)
var operationFailed C.libResult = C.ERR_OPERATION_FAILED

type kem struct {
	kem *C.OQS_KEM
	ctx *C.ctx
}

func (k *kem) KeyPair() (publicKey, secretKey []byte, err error) {
	if k.kem == nil {
		return nil, nil, errAlreadyClosed
	}

	pubKeyLen := C.int(k.kem.length_public_key)
	pk := C.malloc(C.ulong(pubKeyLen))
	defer C.free(unsafe.Pointer(pk))

	secretKeyLen := C.int(k.kem.length_secret_key)
	sk := C.malloc(C.ulong(secretKeyLen))
	defer C.free(unsafe.Pointer(sk))

	res := C.KeyPair(k.kem, (*C.uchar)(pk), (*C.uchar)(sk))
	if res != C.ERR_OK {
		return nil, nil, libError(res, "key pair generation failed")
	}

	return C.GoBytes(pk, pubKeyLen), C.GoBytes(sk, secretKeyLen), nil
}

func (k *kem) Encaps(public []byte) (sharedSecret, ciphertext []byte, err error) {
	if k.kem == nil {
		return nil, nil, errAlreadyClosed
	}

	sharedSecretLen := C.int(k.kem.length_shared_secret)
	s := C.malloc(C.ulong(sharedSecretLen))
	defer C.free(unsafe.Pointer(s))

	ciphertextLen := C.int(k.kem.length_ciphertext)
	ct := C.malloc(C.ulong(ciphertextLen))
	defer C.free(unsafe.Pointer(ct))

	pub := C.CBytes(public)
	defer C.free(pub)

	res := C.Encaps(k.kem, (*C.uchar)(pub), (*C.uchar)(ct), (*C.uchar)(s))
	if res != C.ERR_OK {
		return nil, nil, libError(res, "encapsulation failed")
	}

	return C.GoBytes(s, sharedSecretLen), C.GoBytes(ct, ciphertextLen), nil
}

func (k *kem) Decaps(ciphertext, secretKey []byte) (sharedSecret []byte, err error) {
	if k.kem == nil {
		return nil, errAlreadyClosed
	}

	sharedSecretLen := C.int(k.kem.length_shared_secret)
	ss := C.malloc(C.ulong(sharedSecretLen))
	defer C.free(unsafe.Pointer(ss))

	ct := C.CBytes(ciphertext)
	defer C.free(ct)

	sk := C.CBytes(secretKey)
	defer C.free(sk)

	res := C.Decaps(k.kem, (*C.uchar)(ct), (*C.uchar)(sk), (*C.uchar)(ss))
	if res != C.ERR_OK {
		return nil, libError(res, "decapsulation failed")
	}

	return C.GoBytes(ss, sharedSecretLen), nil
}

func (k *kem) Close() error {
	if k.kem == nil {
		return errAlreadyClosed
	}

	res := C.FreeKem(k.ctx, k.kem)
	if res != C.ERR_OK {
		return libError(res, "failed to free KEM")
	}

	k.kem = nil
	return nil
}

func libError(result C.libResult, msg string, a ...interface{}) error {
	// ERR_OPERATION_FAILED is the generic 'something went wrong but we don't know what'
	// message. No need to include this info.
	if result == C.ERR_OPERATION_FAILED {
		return errors.Errorf(msg, a...)
	}

	str := C.GoString(C.errorString(result))
	return errors.Errorf("%s: %s", fmt.Sprintf(msg, a...), str)
}

// A Kem is an implementation of a key encapsulation mechanism (KEM) from liboqs. Use
// GetKem to load a Kem by name. Call Close on the Kem to avoid resource leaks.
type Kem interface {
	// KeyPair generates a new key pair.
	KeyPair() (publicKey, secretKey []byte, err error)

	// Encaps generates a new shared secret and encrypts it under the public key.
	Encaps(public []byte) (sharedSecret, ciphertext []byte, err error)

	// Decaps decrypts an encrypted shared secret.
	Decaps(ciphertext, secretKey []byte) (sharedSecret []byte, err error)

	// Close frees resources uses by this Kem.
	Close() error
}

// Lib stores state for the loaded liboqs library. Call Close to free resources after use.
type Lib struct {
	ctx *C.ctx
}

// Close frees resources used by the library and unloads it.
func (l *Lib) Close() error {
	res := C.Close(l.ctx)
	if res != C.ERR_OK {
		return libError(res, "failed to close library")
	}

	return nil
}

// LoadLib loads the liboqs library. The path parameter is given directly to dlopen, see the dlopen man page
// for details of how path is interpreted. (Paths with a slash are treated as absolute or relative paths). Be
// sure to Close after use to free resources.
func LoadLib(path string) (*Lib, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))

	var ctx *C.ctx
	res := C.New(p, &ctx)
	if res != C.ERR_OK {
		return nil, libError(res, "failed to load module at %q", path)
	}

	return &Lib{ctx: ctx}, nil
}

// GetKem returns a Kem for the specified algorithm. Constants are provided for known algorithms,
// but any string can be provided and will be passed through to liboqs. As a reminder, some algorithms
// need to be explicitly enabled when building liboqs.
func (l *Lib) GetKem(kemType KemType) (Kem, error) {
	cStr := C.CString(string(kemType))
	defer C.free(unsafe.Pointer(cStr))

	var kemPtr *C.OQS_KEM

	res := C.GetKem(l.ctx, cStr, &kemPtr)
	if res != C.ERR_OK {
		return nil, libError(res, "failed to get KEM")
	}

	kem := &kem{
		kem: kemPtr,
		ctx: l.ctx,
	}
	if kem.kem == nil {
		return nil, errAlgDisabledOrUnknown
	}

	return kem, nil
}
