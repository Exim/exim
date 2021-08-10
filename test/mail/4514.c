From CALLER@myhost.test.ex Tue Mar 02 09:44:33 1999
Received: from the.local.host.name ([ip4.ip4.ip4.ip4] helo=myhost.test.ex)
	by myhost.test.ex with esmtp (Exim x.yz)
	(envelope-from <CALLER@myhost.test.ex>)
	id 10HmaY-0005vi-00
	for c@test.ex; Tue, 2 Mar 1999 09:44:33 +0000
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed; d=test.ex;
	s=ses; h=From:To:Subject; bh=/Ab0giHZitYQbDhFszoqQRUkgqueaX9zatJttIU/plc=; b=
	hjRHwrwAxKFsul1+Bj1XU0YSi0cMQO5hzSItwtaAP++3E9DdxAzeenuRmCyL4o5NQSWY9gMArptRz
	C+SlzhM6A==;
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed; d=test.ex;
	s=sel; h=From:To:Subject; bh=/Ab0giHZitYQbDhFszoqQRUkgqueaX9zatJttIU/plc=; b=
	Nl9zWo9kgHM3r0dQF7ACBkLLmXIm3EoW2pkpEBQOIcLJdXg9A7QFo13KsChDlG3cQtqUFDI9ASaKn
	5fUG3yKEnWPBDNftcIj4+iP0TYYOB9eRw/wddfszZJLIR60y2HCOZVyQB/tf6f+J/eDfxm+ic2pvR
	L4dHw+Uo7oZUzJgpU=;
Received: from CALLER by myhost.test.ex with local (Exim x.yz)
	(envelope-from <CALLER@myhost.test.ex>)
	id 10HmaX-0005vi-00
	for c@test.ex; Tue, 2 Mar 1999 09:44:33 +0000
From: nobody@example.com
Message-Id: <E10HmaX-0005vi-00@myhost.test.ex>
Sender: CALLER_NAME <CALLER@myhost.test.ex>
Date: Tue, 2 Mar 1999 09:44:33 +0000

content

