package utils

func Xor(s string) string {
    key := byte(0xFE)
    in := []byte(s)
    out := make([]byte, len(in))

    for i, b := range in {
        out[i] = b ^ key
    }

    return string(out)
}

