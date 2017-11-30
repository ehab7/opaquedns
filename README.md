# opaquedns
opaquedns is experimental python script using twisted framework running a proxy dns server, opaquedns tries to limit or reduces the impact of dns tunneling; specially when tunneling occures over CNAME repsonse, since other suspicious queries like PTR or TXT could be directly blocked based on the type,however that is not the case with CNAME, to sumerized it opaquedns : 
  - keeps count of the CNAME responses query size (number of characters per second)
  - slows down or cuts off responses if the characters per second for same host exceeded certian level. 
  - overwrites ttl if less than certian value.
  - prevents queries with obsoleted type.
  - pervents response if the replay has large CNAME repsonse size.
  - limits the number of CNAME's response one resonse can hold.
  - uppercase CNAME response to weaken chance to inflate illegit compressed response. 
  - whitelist/blacklist for sites.