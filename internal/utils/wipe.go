package utils

import (
    "crypto/rand"
    "runtime"
)

func FillZero(b []byte) {
    for i := range b {
        b[i] = 0
    }

    runtime.KeepAlive(b)
}

func Wipe(b []byte) error {
    if _, err := rand.Read(b); err != nil {
        FillZero(b)
        return err
    }

    runtime.KeepAlive(b)
    return nil
}

