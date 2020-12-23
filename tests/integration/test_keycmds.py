
import time
from integration_setup import setup_test, connect

def test_orgcard():
	'''Tests the server's ORGCARD command'''
	conn = setup_test()

	first_entry = "Type:Organization\r\nIndex:1\r\nName:Acme, Inc.\r\n" \
		"Contact-Admin:ae406c5e-2673-4d3e-af20-91325d9623ca/acme.com\r\nLanguage:en\r\n" \
		"Primary-Verification-Key:ED25519:)8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88\r\n" \
		"Encryption-Key:CURVE25519:@b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG\r\n" \
		"Time-To-Live:14\r\nExpires:20201002\r\nTimestamp:20200901T131313Z\r\n" \
		"Organization-Signature:ED25519:!~f6qw}ZZRT?>QViW%;%B1M6^<#F}b`yy_iB~L4;8T9>lvsPev<p1i}=" \
		"RL=qkVK~Z{+h)ATW44SLX_SH\r\n" \
		"Hash:BLAKE2B-256:D_yXRD0<CEhVLzl3}I`<w!_x8%IrZ%%ch>G-nCGA3\r\n"
	second_entry = "Type:Organization\r\nIndex:2\r\nName:Acme, Inc.\r\n" \
		"Contact-Admin:ae406c5e-2673-4d3e-af20-91325d9623ca/acme.com\r\nLanguage:en\r\n" \
		"Primary-Verification-Key:ED25519:#|S__!gz0405wh_S-^mh9;h%%0cH!qTzhj<y@K=0d\r\n" \
		"Secondary-Verification-Key:ED25519:hKW~1R;Z$yx(?#dv9um)+5Q;;Q)c9y4@^^>vZUi4\r\n" \
		"Encryption-Key:CURVE25519:^EaaBD3m?A;T6eWS^UB*$|a+rToL389r*>j`Mo?1\r\n" \
		"Time-To-Live:14\r\nExpires:20201002\r\nTimestamp:20200901T131313Z\r\n" \
		"Custody-Signature:ED25519:H}VJu+g^w)Jaw@xa~3SJQ@`Ndq=7}MApBu^lhq;LqTo7uyM~<%%x<r*>RWsw" \
		";>N%%EOusF_ZQdH)piZ+l4\r\n" \
		"Organization-Signature:ED25519:!A|>AKvbJM0WLjd9hA^yhr5BEwsMKebzD@i#r~G9VB{H@Xnuv|RE_S" \
		"28<{4|ajS*i9W>doMNdwvHQ<g9\r\n" \
		"Hash:BLAKE2B-256:5>cWv+qZ^-2aa6NVBKz7h19Fh#9m7r$$7av?6YOM\r\n"

	cur = conn.cursor()
	cur.execute(r"INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) " \
		r"VALUES('organization','20200901T131313Z','1',%s,%s);",
		(first_entry, r'BLAKE2B-256:D_yXRD0<CEhVLzl3}I`<w!_x8%IrZ%ch>G-nCGA3'))
	cur.execute(r"INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) " \
		r"VALUES('organization','20200901T131313Z','2',%s,%s);",
		(second_entry, r'BLAKE2B-256:5>cWv+qZ^-2aa6NVBKz7h19Fh#9m7r$$7av?6YOM'))
	conn.commit()

	sock = connect()
	assert sock, "Connection to server at localhost:2001 failed"
	
	sock.send(b'ORGCARD 1\r\n')

	# TODO: This is a hack to get the test to pass -- there is a race condition caused by a lack 
	# of synchronization between the client and server. The proper fix is a class to handle this
	# synchronization
	time.sleep(1)
	response = sock.recv(8192).decode()
	expected_response = ''.join(['102 ITEM 1 2\r\n----- BEGIN ORG ENTRY -----\r\n', first_entry,
		'----- END ORG ENTRY -----\r\n102 ITEM 2 2\r\n----- BEGIN ORG ENTRY -----\r\n',
		second_entry, '----- END ORG ENTRY -----\r\n'])
	assert response == expected_response, 'test_orgcard: bad multi-item response'

	sock.send(b'QUIT\r\n')


if __name__ == '__main__':
	test_orgcard()