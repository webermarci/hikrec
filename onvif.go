package hikrec

import (
	"strconv"
	"time"
)

type Envelope struct {
	Header Header `xml:"Header"`
	Body   Body   `xml:"Body"`
}

type Header struct {
	Action string `xml:"Action"`
}

type Body struct {
	CreatePullPointSubscriptionResponse CreatePullPointSubscriptionResponse `xml:"CreatePullPointSubscriptionResponse"`
	PullMessagesResponse                PullMessagesResponse                `xml:"PullMessagesResponse"`
}

type CreatePullPointSubscriptionResponse struct {
	SubscriptionReference SubscriptionReference `xml:"SubscriptionReference"`
	CurrentTime           string                `xml:"CurrentTime"`
	TerminationTime       string                `xml:"TerminationTime"`
}

type SubscriptionReference struct {
	Address string `xml:"Address"`
}

type PullMessagesResponse struct {
	CurrentTime         string              `xml:"CurrentTime"`
	TerminationTime     string              `xml:"TerminationTime"`
	NotificationMessage NotificationMessage `xml:"NotificationMessage"`
}

type NotificationMessage struct {
	Topic    string   `xml:"Topic"`
	Messages Messages `xml:"Message"`
}

type Messages struct {
	Messages []Message `xml:"Message"`
}

type Message struct {
	Source Source `xml:"Source"`
	Data   Data   `xml:"Data"`
}

type Source struct {
	Items []SimpleItem `xml:"SimpleItem"`
}

type Data struct {
	Items []SimpleItem `xml:"SimpleItem"`
}

type SimpleItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value,attr"`
}

type Device struct {
	ID       string
	Name     string
	XAddr    string
	User     string
	Password string
}

func (device *Device) CreatePullPointSubscription() (CreatePullPointSubscriptionResponse, error) {
	soap := SOAP{
		User:     device.User,
		Password: device.Password,
		Action:   "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest",
		Body: `<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl">
					<InitialTerminationTime>PT180S</InitialTerminationTime>
				</CreatePullPointSubscription>`,
	}

	envelope, err := soap.SendRequest(device.XAddr, "")
	if err != nil {
		return CreatePullPointSubscriptionResponse{}, err
	}

	return envelope.Body.CreatePullPointSubscriptionResponse, nil
}

func (device *Device) PullMessage(address string, to string) ([]Message, error) {
	soap := SOAP{
		User:     device.User,
		Password: device.Password,
		Action:   "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest",
		Body: `<PullMessages xmlns="http://www.onvif.org/ver10/events/wsdl">
					<Timeout>PT3S</Timeout>
					<MessageLimit>10</MessageLimit>
				</PullMessages>`,
		NoDebug: true,
	}

	envelope, err := soap.SendRequest(address, to)
	if err != nil {
		return nil, err
	}

	messages := envelope.Body.PullMessagesResponse.NotificationMessage.Messages.Messages

	if len(messages) == 0 {
		return nil, nil
	}

	return messages, nil
}

func (device *Device) PullRecognitions() (chan Recogniton, error) {
	res, err := device.CreatePullPointSubscription()
	if err != nil {
		return nil, err
	}

	pullAddress := res.SubscriptionReference.Address
	outgoing := make(chan Recogniton)

	go func() {
		for {
			messages, err := device.PullMessage(device.XAddr, pullAddress)
			if err != nil {
				time.Sleep(time.Second)

				res, err := device.CreatePullPointSubscription()
				for err != nil {
					time.Sleep(time.Second)
					res, err = device.CreatePullPointSubscription()
				}
				pullAddress = res.SubscriptionReference.Address
				continue
			}

			if messages == nil {
				continue
			}

			for _, message := range messages {
				recognition := Recogniton{}

				for _, item := range message.Data.Items {
					switch item.Name {
					case "PlateNumber":
						recognition.Plate = item.Value
					case "Likelihood":
						intValue, err := strconv.Atoi(item.Value)
						if err == nil {
							recognition.Likelihood = intValue
						}
					case "Nation":
						recognition.Nation = item.Value
					case "Country":
						recognition.Country = item.Value
					case "VehicleDirection":
						recognition.Direction = item.Value
					case "PictureUri":
						recognition.PictureURL = item.Value
					}
				}

				if recognition.Plate == "" {
					continue
				}

				outgoing <- recognition
			}

		}
	}()

	return outgoing, nil
}
