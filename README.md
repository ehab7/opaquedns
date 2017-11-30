# opaquedns
opaquedns is an experimental proxy dns server using python and twisted framework, opaquedns attempts to reduces the impact of dns tunneling; specially when it occures over CNAME repsonse, while other suspicious queries like PTR or TXT could be directly blocked based on the type, that is not the case with CNAME. to address tunneling over CANAME opaquedns: 
  - keeps count of the CNAME responses query size (number of characters per second)
  - slows down or cuts off responses if the characters per second for same host exceeded certian level. 
  - overwrites ttl if less than certian value.
  - prevents queries with obsoleted type.
  - pervents response if the replay has large CNAME repsonse size.
  - limits the number of CNAME's response one resonse can hold.
  - uppercase CNAME response to weaken chance to inflate illegit compressed response. 
  - whitelist/blacklist for sites.