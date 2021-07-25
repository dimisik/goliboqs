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

package goliboqs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const libPath = "/usr/local/lib/liboqs.so"

func TestRoundTrip(t *testing.T) {

	kems := []KemType{
		OQS_KEM_alg_bike_l1,
		OQS_KEM_alg_bike_l3,
		OQS_KEM_alg_classic_mceliece_348864,
		OQS_KEM_alg_classic_mceliece_348864f,
		OQS_KEM_alg_classic_mceliece_460896,
		OQS_KEM_alg_classic_mceliece_460896f,
		OQS_KEM_alg_classic_mceliece_6688128,
		OQS_KEM_alg_classic_mceliece_6688128f,
		OQS_KEM_alg_classic_mceliece_6960119,
		OQS_KEM_alg_classic_mceliece_6960119f,
		OQS_KEM_alg_classic_mceliece_8192128,
		OQS_KEM_alg_classic_mceliece_8192128f,
		OQS_KEM_alg_hqc_128,
		OQS_KEM_alg_hqc_192,
		OQS_KEM_alg_hqc_256,
		OQS_KEM_alg_kyber_512,
		OQS_KEM_alg_kyber_768,
		OQS_KEM_alg_kyber_1024,
		OQS_KEM_alg_kyber_512_90s,
		OQS_KEM_alg_kyber_768_90s,
		OQS_KEM_alg_kyber_1024_90s,
		OQS_KEM_alg_ntru_hps2048509,
		OQS_KEM_alg_ntru_hps2048677,
		OQS_KEM_alg_ntru_hps4096821,
		OQS_KEM_alg_ntru_hrss701,
		OQS_KEM_alg_ntruprime_ntrulpr653,
		OQS_KEM_alg_ntruprime_ntrulpr761,
		OQS_KEM_alg_ntruprime_ntrulpr857,
		OQS_KEM_alg_ntruprime_sntrup653,
		OQS_KEM_alg_ntruprime_sntrup761,
		OQS_KEM_alg_ntruprime_sntrup857,
		OQS_KEM_alg_saber_lightsaber,
		OQS_KEM_alg_saber_saber,
		OQS_KEM_alg_saber_firesaber,
		OQS_KEM_alg_frodokem_640_aes,
		OQS_KEM_alg_frodokem_640_shake,
		OQS_KEM_alg_frodokem_976_aes,
		OQS_KEM_alg_frodokem_976_shake,
		OQS_KEM_alg_frodokem_1344_aes,
		OQS_KEM_alg_frodokem_1344_shake,
		OQS_KEM_alg_sidh_p434,
		OQS_KEM_alg_sidh_p434_compressed,
		OQS_KEM_alg_sidh_p503,
		OQS_KEM_alg_sidh_p503_compressed,
		OQS_KEM_alg_sidh_p610,
		OQS_KEM_alg_sidh_p610_compressed,
		OQS_KEM_alg_sidh_p751,
		OQS_KEM_alg_sidh_p751_compressed,
		OQS_KEM_alg_sike_p434,
		OQS_KEM_alg_sike_p434_compressed,
		OQS_KEM_alg_sike_p503,
		OQS_KEM_alg_sike_p503_compressed,
		OQS_KEM_alg_sike_p610,
		OQS_KEM_alg_sike_p610_compressed,
		OQS_KEM_alg_sike_p751,
		OQS_KEM_alg_sike_p751_compressed,
	}

	k, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k.Close()) }()

	for _, kemAlg := range kems {
		t.Run(string(kemAlg), func(t *testing.T) {
			//t.Parallel() <-- cannot use this because https://github.com/stretchr/testify/issues/187

			testKEM, err := k.GetKem(kemAlg)
			if err == errAlgDisabledOrUnknown {
				t.Skipf("Skipping disabled/unknown algorithm %q", kemAlg)
			}
			require.NoError(t, err)
			defer func() { require.NoError(t, testKEM.Close()) }()

			publicKey, secretKey, err := testKEM.KeyPair()
			require.NoError(t, err)

			sharedSecret, ciphertext, err := testKEM.Encaps(publicKey)
			require.NoError(t, err)

			recoveredSecret, err := testKEM.Decaps(ciphertext, secretKey)
			require.NoError(t, err)

			assert.Equal(t, sharedSecret, recoveredSecret)
		})
	}
}

func TestBadLibrary(t *testing.T) {
	_, err := LoadLib("bad")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load module")
}

func TestReEntrantLibrary(t *testing.T) {
	k1, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k1.Close()) }()

	k2, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k2.Close()) }()
}

func TestLibraryClosed(t *testing.T) {
	k, err := LoadLib(libPath)
	require.NoError(t, err)
	require.NoError(t, k.Close())

	const expectedMsg = "library closed"

	t.Run("GetKEM", func(t *testing.T) {
		_, err := k.GetKem(KemBike1L1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), expectedMsg)
	})

	t.Run("Close", func(t *testing.T) {
		err := k.Close()
		require.Error(t, err)
		assert.Contains(t, err.Error(), expectedMsg)
	})
}

func TestKEMClosed(t *testing.T) {
	k, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k.Close()) }()

	testKEM, err := k.GetKem(KemKyber512)
	require.NoError(t, err)

	require.NoError(t, testKEM.Close())

	t.Run("KeyPair", func(t *testing.T) {
		_, _, err := testKEM.KeyPair()
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Encaps", func(t *testing.T) {
		_, _, err := testKEM.Encaps(nil)
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Decaps", func(t *testing.T) {
		_, err := testKEM.Decaps(nil, nil)
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Decaps", func(t *testing.T) {
		err := testKEM.Close()
		assert.Equal(t, errAlreadyClosed, err)
	})
}

func TestInvalidKEMAlg(t *testing.T) {
	k, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k.Close()) }()

	_, err = k.GetKem(KemType("this will never be valid"))
	assert.Equal(t, errAlgDisabledOrUnknown, err)
}

func TestLibErr(t *testing.T) {
	// Difficult to test this without a deliberately failing KEM library (which could
	// be a future idea...)

	err := libError(operationFailed, "test%d", 123)
	assert.EqualError(t, err, "test123")
}
