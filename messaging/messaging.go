package messaging

type SealedEnvelope struct {
	Type       string
	Version    string
	Recipient  string
	Sender     string
	Date       string
	PayloadKey string
	Payload    string
}

type Envelope struct {
	Type       string
	Version    string
	Recipient  RecipientInfo
	Sender     SenderInfo
	Date       string
	PayloadKey string
	Payload    MsgBody
}

type RecipientInfo struct {
	// To contains the full recipient address
	To string

	// Sender contains only the domain of origin
	Sender string
}

type SenderInfo struct {
	// From contains the full sender address
	From string

	// Receiver contains only the destination's domain
	Receiver string
}

type MsgBody struct {
	From        string
	To          string
	Date        string
	ThreadID    string
	Subject     string
	Body        string
	Attachments []Attachment
}

type Attachment struct {
	Name string
	Type string
	Data string
}
