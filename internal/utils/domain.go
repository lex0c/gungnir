package utils

import (
    "context"
    "math/rand"
    "strconv"
    "strings"
    "time"
    "math"
)

const (
    maxLabelLen = 23
    minLabelLen = 5
    minPort     = 4000
    maxPort     = 9009
)

var (
    tldList = []string{
        "\xd0\x9d\x91\x93",         // .com
        "\xd0\x91\x8c\x99",         // .org
        "\xd0\x90\x9b\x8a",         // .net
        "\xd0\x97\x91",             // .io
        "\xd0\x9d\x91",             // .co
        "\xd0\x9f\x97",             // .ai
        "\xd0\x86\x87\x84",         // .xyz
        "\xd0\x8a\x9b\x9d\x96",     // .tech
        "\xd0\x92\x97\x88\x9b",     // .live
        "\xd0\x9d\x92\x8b\x9c",     // .club
        "\xd0\x8d\x96\x91\x8e",     // .shop
        "\xd0\x8d\x97\x8a\x9b",     // .site
        "\xd0\x89\x91\x8c\x95",     // .work
        "\xd0\x8d\x8a\x91\x8c\x9b", // .store
    }
    subList = []string{
        "\x89\x89\x89",                 // www
        "\x93\x9f\x97\x92",             // mail
        "\x9f\x8e\x97",                 // api
        "\x9c\x92\x91\x99",             // blog
        "\x8d\x8a\x91\x8c\x9b",         // store
        "\x9f\x8e\x8e",                 // app
        "\x9a\x9b\x88",                 // dev
        "\x8d\x9b\x9d\x8b\x8c\x9b",     // secure
        "\x9f\x9a\x93\x97\x90",         // admin
        "\x8d\x8a\x9f\x99\x97\x90\x99", // staging
        "\x8e\x91\x8c\x8a\x9f\x92",     // portal
        "\x8d\x97\x8a\x9b",             // site
        "\x9d\x96\x9f\x8a",             // chat
        "\x93\x9b\x8a\x8c\x97\x9d\x8d", // metrics
        "\x9d\x91\x92\x92\x9b\x9d\x8a", // collect
    }

    alnum       = "\x9f\x9c\x9d\x9a\x9b\x98\x99\x96\x97\x94\x95\x92\x93\x90\x91\x8e\x8f\x8c\x8d\x8a\x8b\x88\x89\x86\x87\x84\xce\xcf\xcc\xcd\xca\xcb\xc8\xc9\xc6\xc7" // abcdefghijklmnopqrstuvwxyz0123456789
    alnumHyphen = alnum + "\xd3" // -
    alnumLength = 36
)

func GenDomainsStreamCtx(ctx context.Context, seed int64, length int) <-chan string {
    if length < minLabelLen {
        length = minLabelLen
    }

    if length > maxLabelLen {
        length = maxLabelLen
    }

    r := rand.New(rand.NewSource(seed))

    out := make(chan string, 128)
    go func() {
        defer close(out)
        for i := 0; i < math.MaxInt; i++ {
            actual := length - safeIntn(r, 3)
            if actual < minLabelLen {
                actual = minLabelLen
            }

            label := makeLabel(actual, r)

            var b strings.Builder
            if prob(30, r) {
                b.WriteString(Xor(subList[safeIntn(r, len(subList))]))
                b.WriteByte('.')
            }

            b.WriteString(label)
            b.WriteString(Xor(tldList[safeIntn(r, len(tldList))]))
            b.WriteByte(':')

            port := randomFreePort(r, minPort, maxPort)
            b.WriteString(strconv.Itoa(port))

            select {
            case <-ctx.Done():
                return
            case out <- b.String():
            }
        }
    }()

    return out
}

func GenDomainsStream(seed int64, length int) <-chan string {
    ctx, cancel := context.WithCancel(context.Background())
    ch := GenDomainsStreamCtx(ctx, seed, length)

    go func() {
        time.Sleep(10 * time.Minute)
        cancel()
    }()

    return ch
}

func makeLabel(n int, r *rand.Rand) string {
    b := make([]byte, n)
    b[0] = Xor(alnum)[safeIntn(r, alnumLength)]
    for i := 1; i < n-1; i++ {
        b[i] = Xor(alnumHyphen)[safeIntn(r, alnumLength+1)]
    }
    b[n-1] = Xor(alnum)[safeIntn(r, alnumLength)]

    if n >= 4 && b[0] == 'x' && b[1] == 'n' && b[2] == '-' && b[3] == '-' {
        b[1] = 'm'
    }

    return string(b)
}

func prob(percent int, r *rand.Rand) bool {
    if percent <= 0 {
        return false
    }

    if percent >= 100 {
        return true
    }

    return safeIntn(r, 100) < percent
}

func safeIntn(r *rand.Rand, n int) int {
    if n <= 1 {
        return 0
    }

    return r.Intn(n)
}

func randomFreePort(r *rand.Rand, min, max int) (int) {
    return r.Intn(max-min+1) + min
}

