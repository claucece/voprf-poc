package ecgroup

import (
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"math/big"

	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
	"github.com/cloudflare/circl/ecc/p384"
)

// baseCurve extends the standard elliptic curve interface
type baseCurve interface {
	elliptic.Curve
}

// ExtendedCurve adds functionality required for performing curve operations
type ExtendedCurve interface {
	gg.PrimeOrderGroup
	Name() string
	Hash() hash.Hash
}

// GroupCurve implements the ExtendedCurve interface
type GroupCurve struct {
	ops  baseCurve
	name string
	hash hash.Hash
	nist bool
}

// Order returns the order of the underlying field for the baseCurve object
func (c GroupCurve) Order() *big.Int {
	return c.ops.Params().P
}

// Generator returns the point in the curve representing the generator for the
// instantiated prime-order group
func (c GroupCurve) Generator() Point {
	return Point{
		X: c.ops.Params().Gx,
		Y: c.ops.Params().Gy,
	}
}

// EncodeToGroup invokes the hash_to_curve method for encoding bytes as curve
// points
func (c GroupCurve) EncodeToGroup(buf []byte) (Point, error) {
	params, err := getH2CParams(c)
	if err != nil {
		return Point{}, err
	}
	p, err := params.hashToCurve(buf)
	if err != nil {
		return Point{}, err
	}
	return p, nil
}

// Name returns the name of the NIST P-384 curve
func (c GroupCurve) Name() string { return c.name }

// Hash returns the name of the hash function used in conjunction with the NIST
// P-384 curve
func (c GroupCurve) Hash() hash.Hash { return c.hash }

// P384 provides access to the NIST P-384 curve
func P384() GroupCurve {
	return GroupCurve{
		ops:  p384.P384(),
		name: "P-384",
		hash: sha512.New(),
		nist: true,
	}
}

// P521 provides access to the NIST P-521 curve
func P521() GroupCurve {
	return GroupCurve{
		ops:  elliptic.P521(),
		name: "P-521",
		hash: sha512.New(),
		nist: true,
	}
}

// Point implements the Group interface and is compatible with the Curve
// Group-type
type Point struct {
	X, Y *big.Int
}

// IsValid checks that the given point is a valid curve point for the input
// GroupCurve Object
func (p Point) IsValid(curve GroupCurve) bool {
	return curve.ops.IsOnCurve(p.X, p.Y)
}

// ScalarMult multiplies p by the provided Scalar value, and returns p or an
// error
func (p Point) ScalarMult(curve GroupCurve, k *big.Int) (Point, error) {
	if !p.IsValid(curve) {
		return Point{}, gg.ErrInvalidGroupElement
	}
	p.X, p.Y = curve.ops.ScalarMult(p.X, p.Y, k.Bytes())
	return p, nil
}

// Add adds pAdd to p and returns p or an error
func (p Point) Add(curve GroupCurve, pAdd Point) (Point, error) {
	if !p.IsValid(curve) {
		return Point{}, gg.ErrInvalidGroupElement
	}
	p.X, p.Y = curve.ops.Add(p.X, p.Y, pAdd.X, pAdd.Y)
	return p, nil
}

// Serialize marshals the point object into an octet-string, returns nil if
// serialization is not supported for the given curve
func (p Point) Serialize(curve GroupCurve, compressed bool) []byte {
	if curve.nist {
		return p.nistSerialize(compressed)
	}
	return nil
}

// nistSerialize marshals the point object into an octet-string of either
// compressed or uncompressed SEC1 format
// (https://www.secg.org/sec1-v2.pdf#subsubsection.2.3.3)
func (p Point) nistSerialize(compressed bool) []byte {
	xBytes, yBytes := p.X.Bytes(), p.Y.Bytes()
	var bytes []byte
	var tag int
	if !compressed {
		bytes = append(xBytes, yBytes...)
		tag = 4
	} else {
		bytes = xBytes
		tag = subtle.ConstantTimeSelect(int(yBytes[0])&1, 3, 2)
	}
	return append([]byte{byte(tag)}, bytes...)
}

// TODO
// Deserialize creates a point object from an octet-string according to the SEC1
// specification (https://www.secg.org/sec1-v2.pdf#subsubsection.2.3.4)
func (p Point) Deserialize(curve GroupCurve) (Point, error) {
	return Point{}, nil
}

// clearCofactor clears the cofactor (hEff) of p by performing a scalar
// multiplication and returning p or an error
func (p Point) clearCofactor(curve GroupCurve, hEff *big.Int) (Point, error) {
	return p.ScalarMult(curve, hEff)
}
