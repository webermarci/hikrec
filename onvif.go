package hikrec

import (
	"strconv"
	"time"
)

type envelope struct {
	Header header `xml:"Header"`
	Body   body   `xml:"Body"`
}

type header struct {
	Action string `xml:"Action"`
}

type body struct {
	CreatePullPointSubscriptionResponse createPullPointSubscriptionResponse `xml:"CreatePullPointSubscriptionResponse"`
	PullMessagesResponse                pullMessagesResponse                `xml:"PullMessagesResponse"`
}

type createPullPointSubscriptionResponse struct {
	SubscriptionReference subscriptionReference `xml:"SubscriptionReference"`
	CurrentTime           string                `xml:"CurrentTime"`
	TerminationTime       string                `xml:"TerminationTime"`
}

type subscriptionReference struct {
	Address string `xml:"Address"`
}

type pullMessagesResponse struct {
	CurrentTime         string              `xml:"CurrentTime"`
	TerminationTime     string              `xml:"TerminationTime"`
	NotificationMessage notificationMessage `xml:"NotificationMessage"`
}

type notificationMessage struct {
	Topic    string   `xml:"Topic"`
	Messages messages `xml:"Message"`
}

type messages struct {
	Messages []message `xml:"Message"`
}

type message struct {
	Source source `xml:"Source"`
	Data   data   `xml:"Data"`
}

type source struct {
	Items []simpleItem `xml:"SimpleItem"`
}

type data struct {
	Items []simpleItem `xml:"SimpleItem"`
}

type simpleItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value,attr"`
}

type Device struct {
	ID       string
	Name     string
	Url      string
	Username string
	Password string
}

func NewDevice(url, username, password string) *Device {
	return &Device{
		Url:      url,
		Username: username,
		Password: password,
	}
}

func (device *Device) createPullPointSubscription() (createPullPointSubscriptionResponse, error) {
	soap := soap{
		User:     device.Username,
		Password: device.Password,
		Action:   "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest",
		Body:     "<CreatePullPointSubscription xmlns=\"http://www.onvif.org/ver10/events/wsdl\"><InitialTerminationTime>PT180S</InitialTerminationTime></CreatePullPointSubscription>",
	}

	envelope, err := soap.sendRequest(device.Url, "")
	if err != nil {
		return createPullPointSubscriptionResponse{}, err
	}

	return envelope.Body.CreatePullPointSubscriptionResponse, nil
}

func (device *Device) pullMessage(address string, to string) ([]message, error) {
	soap := soap{
		User:     device.Username,
		Password: device.Password,
		Action:   "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest",
		Body:     "<PullMessages xmlns=\"http://www.onvif.org/ver10/events/wsdl\"><Timeout>PT3S</Timeout><MessageLimit>10</MessageLimit></PullMessages>",
	}

	envelope, err := soap.sendRequest(address, to)
	if err != nil {
		return nil, err
	}

	messages := envelope.Body.PullMessagesResponse.NotificationMessage.Messages.Messages

	if len(messages) == 0 {
		return nil, nil
	}

	return messages, nil
}

func (device *Device) PullRecognitions() (chan Recognition, error) {
	res, err := device.createPullPointSubscription()
	if err != nil {
		return nil, err
	}

	pullAddress := res.SubscriptionReference.Address
	outgoing := make(chan Recognition)

	go func() {
		for {
			start := time.Now()

			messages, err := device.pullMessage(device.Url, pullAddress)
			if err != nil {
				res, err := device.createPullPointSubscription()
				for err != nil {
					time.Sleep(time.Second)
					res, err = device.createPullPointSubscription()
				}
				pullAddress = res.SubscriptionReference.Address
				continue
			}

			if messages == nil {
				continue
			}

			for _, message := range messages {
				recognition := Recognition{}

				for _, item := range message.Data.Items {
					switch item.Name {
					case "PlateNumber":
						recognition.Plate = item.Value
					case "Likelihood":
						intValue, err := strconv.Atoi(item.Value)
						if err == nil {
							if intValue > 100 {
								recognition.Confidence = intValue / 10
							} else {
								recognition.Confidence = intValue
							}
						}
					case "Nation":
						recognition.Nation = item.Value
					case "Country":
						recognition.Country = item.Value
					case "VehicleDirection":
						switch item.Value {
						case "reverse":
							recognition.Direction = Leaving
						case "forward":
							recognition.Direction = Approaching
						default:
							recognition.Direction = Unknown
						}
					}
				}

				if recognition.Plate == "" || recognition.Plate == "unknown" {
					continue
				}

				recognition.CameraResponseDuration = time.Since(start)
				outgoing <- recognition
			}
		}
	}()

	return outgoing, nil
}
