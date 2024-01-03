package messaging

import (
	"errors"

	"gitlab.com/mensago/mensagod/types"
)

//	{
//	    "Type" : "sysmessage",
//	    "Subtype" : "devrequest",
//	    "Version" : "1.0",
//	    "From" : "mensago-example.com",
//	    "To" : "662679bd-3611-4d5e-a570-52812bdcc6f3/example.com",
//	    "Date" : "2022-05-05T10:07:56Z",
//	    "Format": "text",
//	    "Subject" : "New Device Approval",
//	    "Body" : "Time:2022-05-05T10:07:56Z\r\nExpires:2022-05-05T18:07:56Z\r\nIP:12.80.0.162\r\nLocation:Morristown, New Jersey\r\n",
//	    "Attachments": [{
//	        "Name": "deviceinfo",
//	        "Type": "application/vnd.mensago.encrypted-json",
//	        "Data": "CURVE25519:{UfJ=rOoXjUA-Q$rBMw<70Q{eK&ro?HYKGB$zPtG",
//	    }]
//	}
func NewDeviceApproval(info messageInfo, devid types.RandomID) (*SealedEnvelope, error) {

	return nil, errors.New("NewDeviceApproval unimplemented")
}
