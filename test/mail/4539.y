From MAILER-DAEMON Tue Mar 02 09:44:33 1999
Return-path: <>
Received: from localhost ([127.0.0.1] helo=testhost.test.ex)
	by testhost.test.ex with esmtps (TLS1.x:ke-RSA-AES256-SHAnnn:xxx)
	(Exim x.yz)
	id 10HmaY-0005vi-00
	for y@test.ex;
	Tue, 2 Mar 1999 09:44:33 +0000
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed; d=test.ex;
	s=sel; h=Subject; bh=qrFAgZTdNItSIrBZpDPHl7T6nHDpDTlw6cFlhULnt3c=; b=XGR6pjWM
	PEWqcZj6/UQcH54guCxLNrtBaOS6Bve1+prubUxn6u3FdP+deLkkZTMrgf2LUMg3APxC4moIREkTt
	7JmnHBYDEeNOsV8Zpg95yRp+8BIEAqBGddOIs2KzUb3Ua0B2gbVd8Ovc2hrMu+JJPx9CE1mlHtHIw
	txPmCs15I=;
Received: from [127.0.0.1] (helo=xxx)
	by testhost.test.ex with smtps (TLS1.x:ke-RSA-AES256-SHAnnn:xxx)
	(Exim x.yz)
	(envelope-from <CALLER@bloggs.com>)
	id 10HmbA-0005vi-00
	for y@test.ex;
	Tue, 2 Mar 1999 09:44:33 +0000
Subject: simple test
X-body-linecount: 0
X-message-linecount: 19
X-received-count: 2

Line 1: This is a simple test.
Line 2: This is a simple test.
.Line 3 has a leading dot
extra32chars234567890123456789
last line: 4

