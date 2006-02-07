# Exim filter

headers remove remove
headers add "added: this header is added"
headers add "adrem: this header is added and then removed"
headers remove adrem
