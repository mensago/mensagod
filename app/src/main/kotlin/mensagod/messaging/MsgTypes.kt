package mensagod.messaging

import keznacl.CryptoString
import libkeycard.Domain
import libkeycard.MAddress
import libkeycard.RandomID
import libkeycard.Timestamp

/**
 * The RecipientInfo class contains the information used by the receiving domain's server to
 * deliver a message to its recipient.
 */
class RecipientInfo(var to: MAddress, var senderDom: Domain)

/**
 * The SenderInfo class contains the information used by the sending domain's server to
 * deliver a message to the server for its recipient.
 */
class SenderInfo(var from: MAddress, var recipientDom: Domain)

/**
 * The Envelope is a data structure class which represents the public delivery information for a
 * message.
 */
class Envelope(var type: String, var version: String, var receiver: RecipientInfo,
               var sender: SenderInfo, var date: Timestamp, var payloadKey: CryptoString)

/**
 * The Attachment class holds the data used for file attachments to messages and other data models
 */
class Attachment(var name: String, var type: String, var data: String)

/** The MsgBody class is a model for unencrypted messages */
class MsgBody(var from: String, var to: String, var date: Timestamp, var threadID: RandomID,
              var subject: String, var body: String, var attachments: MutableList<Attachment>)
