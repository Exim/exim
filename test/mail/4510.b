From CALLER@myhost.test.ex Tue Mar 02 09:44:33 1999
Received: from the.local.host.name ([ip4.ip4.ip4.ip4] helo=myhost.test.ex)
	by myhost.test.ex with esmtp (Exim x.yz)
	(envelope-from <CALLER@myhost.test.ex>)
	id 10HmbB-0005vi-00
	for b@test.ex; Tue, 2 Mar 1999 09:44:33 +0000
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed; d=test.ex;
	s=sel; h=From:From; bh=/Ab0giHZitYQbDhFszoqQRUkgqueaX9zatJttIU/plc=;
	t=T; x=T+10; b=bbbb;
Received: from CALLER by myhost.test.ex with local (Exim x.yz)
	(envelope-from <CALLER@myhost.test.ex>)
	id 10HmbA-0005vi-00
	for b@test.ex; Tue, 2 Mar 1999 09:44:33 +0000
From: nobody@example.com
Message-Id: <E10HmbA-0005vi-00@myhost.test.ex>
Sender: CALLER_NAME <CALLER@myhost.test.ex>
Date: Tue, 2 Mar 1999 09:44:33 +0000

content

