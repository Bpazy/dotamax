package dotamax

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strconv"
)

func Encrypt(content string) string {
	rsaE := "10001"
	rsaN := "B81E72A33686A201B0AC009D679750990E3D168670DC6F9452C24E5A4C299AC002C6C89C3CB38784AEA95D66B7B3E9CA950EB9EEFB4EF61383EDDB67C35727F9CA87EE3238346C66D042B35812179501F472AD4F3BA19E701256FE0435AB856E5C5BEA24A2387153023CD4CD43CDA7260FCC1E2E49C14102C253F559F9A45D59DF5004A017B1239448A9A001D276CAD12535DEDE89FFBD57D75BBC9B575530DDD1B7FAD46064AD3C640CBD017F58981215B2EE17CBE175C36570C5235902818648577234E70E81133B088164F98E605D0D6E69A6095A32A72511E9AC901727B635CE2E8002A7B0EC8D012606903BCB825E60C7B6619FFCED4401E693F5EC68AB"

	n := new(big.Int)
	n, ok := n.SetString(rsaN, 16)
	if !ok {
		panic("public key should be hexadecimal")
	}

	hexRsaE, err := strconv.ParseInt(rsaE, 16, 64)
	if err != nil {
		panic(err)
	}
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, &rsa.PublicKey{
		N: n,
		E: int(hexRsaE),
	}, []byte(content))
	if err != nil {
		panic(err)
	}
	return linebrk(base64.StdEncoding.EncodeToString(encryptedData), 64)
}

func linebrk(s string, n int) string {
	var ret = ""
	var i = 0
	for i+n < len(s) {
		ret += s[i:i+n] + "\n"
		i += n
	}
	return ret + s[i:]
}
