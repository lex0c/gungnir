package main

import (
    "strconv"
)

// seedStr holds the domain generation seed as a string. It can be set at
// build time using `-ldflags "-X main.seedStr=VALUE"`.
var seedStr string

// dgaSeed is the numeric seed used to generate domain names. It defaults to 23
// but may be overridden via seedStr.
var dgaSeed int64 = 23

func init() {
    if seedStr == "" {
        return
    }

    if v, err := strconv.ParseInt(seedStr, 10, 64); err == nil {
        dgaSeed = v
    }
}
