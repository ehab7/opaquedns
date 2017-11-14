# opaquedns
opaquedns is python script using twisted framework to runs a dns proxy server, opaquedns trying to limit or reduce the impact of dns tunneling; specially when tunneling occure over CNAME repsonse, other suspicious queries types like PTR or TXT can directly blocked based on the type,however that can not the case with CNAME, so opaquedns: 
  - keeps count of the CNAME responses query size (number of characters per second)
  - slows down or cuts off responses if the characters per second for same host exceeded certian level. 
  - overwrites ttl if less than certian value.
  - prevents queries with obsoleted type.
  - pervents response if the replay has large CNAME repsonse size.
  - limits the number of CNAME's response one resonse can hold.
  - uppercase CNAME response to weaken chance to inflate illegit compressed response. 
  - whitelist/blacklist for sites.