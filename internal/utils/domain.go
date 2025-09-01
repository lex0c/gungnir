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
    tldList = []string{".com", ".org", ".net", ".io", ".co", ".ai", ".xyz", ".tech", ".live", ".club", ".shop", ".site", ".work", ".store"}
    subList = []string{"www", "mail", "api", "blog", "store", "app", "dev", "secure", "admin", "staging", "portal", "site", "chat", "metrics", "collect"}

    alnum       = "abcdefghijklmnopqrstuvwxyz0123456789"
    alnumHyphen = alnum + "-"
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
                b.WriteString(subList[safeIntn(r, len(subList))])
                b.WriteByte('.')
            }

            b.WriteString(label)
            b.WriteString(tldList[safeIntn(r, len(tldList))])
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
    b[0] = alnum[safeIntn(r, len(alnum))]
    for i := 1; i < n-1; i++ {
        b[i] = alnumHyphen[safeIntn(r, len(alnumHyphen))]
    }
    b[n-1] = alnum[safeIntn(r, len(alnum))]

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

