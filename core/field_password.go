// test-only dummy token placeholder
const testJWT = "<redacted-test-token>"

// or generate a token at runtime using a test-only signing key
func makeTestJWT(t *testing.T, claims map[string]any) string {
    key := []byte("test-only-non-production-secret")
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
    signed, err := token.SignedString(key)
    require.NoError(t, err)
    return signed
}