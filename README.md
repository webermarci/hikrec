# Hikvision licence plate recognition library

## Usage

```go
import "github.com/webermarci/hikrec"

device := hikrec.NewDevice("192.168.1.10", "admin", "12345")

channel, err := device.PullRecognitions()
if err != nil {
    panic(err)
}

for recognition := range channel {
    ...
}
```