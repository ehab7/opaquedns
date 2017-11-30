#!/usr/bin/env python
# -*- coding: utf-8 -*-


from twisted.names import dns, server, client, cache,error
from twisted.application import service, internet
from twisted.internet import task,reactor,defer
import sys,re,time
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DNSResolver(client.Resolver):
    # example for blacklisting site like anti-verus..etc
    blackListDNS = [re.compile(".*\.mcafee\.com$"),
                    re.compile(".*\.sophosxl\.net$"),
                    re.compile(".*\.sophos\.net$"),
                    re.compile(".*\.kaspersky\.com$")]
    
    #https://en.wikipedia.org/wiki/List_of_DNS_record_types  obsoleted type is blocked.
    blackListRecordType = [3,4,254,7,8,9,14,253,11,32 ,33,0,38,30 ,13,17,19,20 ,21,22,23 , \
                           26,31,32 ,34,42,40,27,100, 101,102,103,99]
    
    # example for whitelisting site like google..etc
    whiteListDNS = [re.compile(".*\.google\.com$")]

    # regEX to extract site name 
    siteRegx     = re.compile(".*\.(.*)\.(.*)")

    # min TTL 
    minTTL = 1200

    # delay response if the response exceed certain rate
    respDelayBy = 3

    # max response char length
    maxRespNameLen = 200

    # max request char length
    maxReqNameLen = 200

    # the cut off rate is the max allowed rate characters per second so 10kbps is around ~1250
    maxSiteCharsRate = 1250

    # the slow down rate is the rate (characters) per second which response will be delayed by 5 seconds. 
    slowSiteAtByteRate = 900

    totalCnameRecords = 4

    totalARecords = 3

    upperName = True

    bigDict = {}

    def __init__(self, servers):
        client.Resolver.__init__(self, servers=servers)
        self.decay = task.LoopingCall(DNSResolver.runEverySecond)
        self.decay.start(1.0)

    @staticmethod
    def checkWhiteList(txt):
        for each in DNSResolver.whiteListDNS:
            if each.match(txt):
                logger.info("site {} is whitelisted".format(txt)) 
                return True

    @staticmethod
    def checkBlackList(txt):
        for each in DNSResolver.blackListDNS:
            if each.match(txt):
                logger.info("site {} is blacklisted".format(txt)) 
                return True

    @staticmethod
    def checkSite(site):
        y = DNSResolver.bigDict.get(site,0)
        if y:
            y = int(y.split('_')[0])
        return y

    @staticmethod
    def updateSite(site,size):
        if len(DNSResolver.bigDict) > 30000:
            logging.warn("skip updates dictionary is too big") 
            return 
        x = DNSResolver.bigDict.get(site,0)
        if x:
            record = x.split('_')
            x = int(record[0])
        total = x + size
        DNSResolver.bigDict[site] = "{}_{}".format(total,int(time.time()))

    @staticmethod
    def runEverySecond():
        when = int(time.time())
        for each in DNSResolver.bigDict.keys():
            record = map(int,DNSResolver.bigDict[each].split('_'))
            value = record[0]
            stamp = record[1]
            diff = when - stamp
            if diff > 1:
                r = int(value/diff)
                if r == 0:
                    DNSResolver.bigDict.pop(each,None)
                else:
                    DNSResolver.bigDict[each] = "{}_{}".format(r,when)


    def specialLookUp(self,result):
        authority = []
        additional = []
        answers = []
        aRecords = [0] # use list to workaround nested func can't rebind nonlocal vars. 
        cRecords = [0]
        


        # low down the suspected requests
        def slowDownResponse(f):
            return result[0],result[1],[]


        def processAnswer(readBack):
            count,i=readBack[0],readBack[1]
            if i >= len(result[0]):
                if len(answers) < 1 : # in case couldn't build any answer use the org one
                    logger.warn("can not build reply use the orginal answer ")
                    return result[0],result[1],[]
                return answers, authority, additional


            answer = result[0][i]
            slowDown = False
            if count and count > DNSResolver.maxSiteCharsRate:
                logger.debug("execeed the max site characters rate")
                return defer.fail(error.DomainError())
            else:
                if count and count > DNSResolver.slowSiteAtByteRate:
                    slowDown = True
                    
                if answer.type == dns.CNAME  and cRecords[0] < DNSResolver.totalCnameRecords:
                    siteName = b"%s"%answer.name
                    siteCName = getattr(answer.payload, "name", "")
                    siteCName = b"%s"%siteCName
                    if len(siteCName) > DNSResolver.maxRespNameLen: return defer.fail(error.DomainError())

                    siteRe = DNSResolver.siteRegx.match(siteName)
                    if siteRe:
                        DNSResolver.updateSite(siteRe.groups()[0] + siteRe.groups()[1],len(siteCName))

                    if answer.ttl < DNSResolver.minTTL:
                        answer.ttl = DNSResolver.minTTL
                    siteCName = siteCName if not DNSResolver.upperName else siteCName.upper()

                    answers.append(dns.RRHeader(siteName,
                        answer.type,
                        dns.IN,
                        answer.ttl,
                        dns.Record_CNAME(b"%s"%siteCName),
                        auth=False))
                    cRecords[0] +=  1

                elif answer.type == dns.A and aRecords[0] < DNSResolver.totalARecords:
                    siteName = b"%s"%answer.name
                    
                    siteName = siteName if not DNSResolver.upperName else siteName.upper()
                    addrDot = answer.payload.dottedQuad()
                    if answer.ttl < DNSResolver.minTTL:
                        answer.ttl = DNSResolver.minTTL
                    answers.append(
                        dns.RRHeader(name=siteName,
                        payload=dns.Record_A(address=addrDot),
                        ttl=answer.ttl))
                    aRecords[0] +=  1

                if slowDown == True:
                    return task.deferLater(reactor, DNSResolver.respDelayBy , slowDownResponse, None)
                else:    
                    return processAnswer([count,i+1])

        def handler():
            if result and len(result[0]):
                siteName = str(result[0][0].name)
            else:
                siteName = ""
            siteReg = DNSResolver.siteRegx.match(siteName)
            domain = ""
            if siteReg:
                domain = siteReg.groups()[0] + siteReg.groups()[1]
            der = DNSResolver.checkSite(domain)
            return processAnswer([der,0])

        if DNSResolver.checkWhiteList(str(result[0][0].name)): return result
        return handler()      
     
    def lookupText(self,name,timeout):
        def handler(result):
            for authory in result[1]:
                siteName = str(authory.name)
                if len(siteName) > DNSResolver.maxRespNameLen: return defer.fail(error.DomainError())
            return result

        s = client.Resolver.lookupText(self,name,timeout)
        return s.addCallback(handler)


    def query(self, query, timeout=5):
        # example of explicit blocking of record type PTR
        if query.type == dns.PTR:
            return defer.fail(error.DomainError())

        if query.type in DNSResolver.blackListRecordType:
            return defer.fail(error.DomainError())
        
        if DNSResolver.checkBlackList(b"%s"%query.name): 
            return  defer.fail(error.DomainError())

        return client.Resolver.query(self,query,timeout)

    def lookupAddress(self,name,timeout=None):
        if len(name) > DNSResolver.maxReqNameLen:
            return defer.fail(error.DomainError())
        else:
            result = client.Resolver.lookupAddress(self,name,timeout)
            result.addCallback(self.specialLookUp)
            return result



if __name__ == '__main__':
    # test for testing probably you should use bind to caching the results
    print "using 8.8.8.8 and 8.8.4.4 as our forwarders"
    db_dns_resolver = DNSResolver( [("8.8.8.8", 53), ("8.8.4.4", 53)] )
    f = server.DNSServerFactory(clients=[db_dns_resolver])
    p = dns.DNSDatagramProtocol(f)    
    f.noisy = p.noisy = False

    # runing a proxy on port 10053
    reactor.listenUDP(10053, p)
    reactor.listenTCP(10053, f)
    reactor.run()