From CALLER@myhost.test.ex Tue Mar 02 09:44:33 1999
Received: from the.local.host.name ([ip4.ip4.ip4.ip4] helo=myhost.test.ex)
	by myhost.test.ex with esmtp (Exim x.yz)
	(envelope-from <CALLER@myhost.test.ex>)
	id 10HmbA-000000005vi-0000
	for b@test.ex;
	Tue, 2 Mar 1999 09:44:33 +0000
DKIM-Signature: v=1; a=ed25519-sha256; q=dns/txt; c=relaxed/relaxed; d=test.ex
	; s=sed; h=From; bh=/Ab0giHZitYQbDhFszoqQRUkgqueaX9zatJttIU/plc=; b=IKNwoUbCe
	ayHoA7j2L0IU1IFuapa3DrlNx9wPlBodM1iKJ57WGibKzefQNdTjymHPsMlQ9fS+h9ZSsHmVNBdDA
	==;
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed; d=test.ex;
	s=sel; h=From; bh=/Ab0giHZitYQbDhFszoqQRUkgqueaX9zatJttIU/plc=; b=toy5chxow6W
	7Nn3qMvjZs+i0H00bQfi+6nakV6i36cRrZM/oWziHrc5IfYZuQunWNUA9UHnatK35Nsl7ZJRBU4em
	wtzdO60jXnH7ZVyYjKxqTow9uCuuBKCgXdKxt1hpEfY0m7uUKt9OaqA0464NH5wEC4o/pt1aReidE
	hvI6IY=;
Received: from CALLER by myhost.test.ex with local (Exim x.yz)
	(envelope-from <CALLER@myhost.test.ex>)
	id 10HmaZ-000000005vi-0000
	for b@test.ex;
	Tue, 2 Mar 1999 09:44:33 +0000
From: nobody@example.com
Message-Id: <E10HmaZ-000000005vi-0000@myhost.test.ex>
Sender: CALLER_NAME <CALLER@myhost.test.ex>
Date: Tue, 2 Mar 1999 09:44:33 +0000

content

