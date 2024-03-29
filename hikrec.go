package hikrec

import "time"

type Direction string

const (
	Approaching Direction = "Approaching"
	Leaving     Direction = "Leaving"
	Unknown     Direction = "Unknown"
)

type Recognition struct {
	Plate                  string        `json:"plate"`
	Confidence             int           `json:"confidence"`
	Direction              Direction     `json:"direction"`
	Country                string        `json:"country"`
	Nation                 string        `json:"nation"`
	CameraResponseDuration time.Duration `json:"camera_response_duration"`
}
