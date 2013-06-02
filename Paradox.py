#!/usr/bin/env python
# Paradox - Web Application Firewall Detection Tool
# by Azizjon Mamashoev (c) 2013

__license__ = """
Copyright (c) 2013, {Azizjon Mamashoev}
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of EnableSecurity or Trustwave nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import os
import httplib
from urllib import quote, unquote
import urllib2
from optparse import OptionParser
import logging
import socket
import sys

currentDir = os.getcwd()
scriptDir = os.path.dirname(sys.argv[0]) or '.'
os.chdir( scriptDir )

from libs.evillib import *

__version__ = '1.9.0'

lackofart = """
  ________/\________  /\_____  ________ ____
  \_____  \ \_____  \/  \___ \/    \   |   / 
    /  ___/| \|  /  /  | \ |  \  |  \     /  
   /   |   _  \  \  \  _  \    \    /     \  
  /    |___|   \_|\__\_|   \___/___/___|   \ 
 /_____|---|____\------|____\----------|____\
    Paradox - Web Application Firewall Detection Tool
    
    By Azizjon Mamashoev
"""


class Paradox(paradoxengine):
    """
    WAF detection tool
    """
    
    xssstring = '<script>alert(1)</script>'
    dirtravstring = '../../../../etc/passwd'
    cleanhtmlstring = '<invalid>hello'
    
    def __init__(self,target='www.microsoft.com',port=80,ssl=False,
                 debuglevel=0,path='/',followredirect=True):
        """
        target: the hostname or ip of the target server
        port: defaults to 80
        ssl: defaults to false
        """
        paradoxengine.__init__(self,target,port,ssl,debuglevel,path,followredirect)
        self.log = logging.getLogger('Paradox')
        self.knowledge = dict(generic=dict(found=False,reason=''),wafname=list())
        
    def normalrequest(self,usecache=True,cacheresponse=True,headers=None):
        return self.request(usecache=usecache,cacheresponse=cacheresponse,headers=headers)
    
    def normalnonexistentfile(self,usecache=True,cacheresponse=True):
        import random
        path = self.path + str(random.randrange(1000,9999)) + '.html'
        return self.request(path=path,usecache=usecache,cacheresponse=cacheresponse)
    
    def unknownmethod(self,usecache=True,cacheresponse=True):
        return self.request(method='OHYEA',usecache=usecache,cacheresponse=cacheresponse)
    
    def directorytraversal(self,usecache=True,cacheresponse=True):
        return self.request(path=self.path+self.dirtravstring,usecache=usecache,cacheresponse=cacheresponse)
        
    def cleanhtmlencoded(self,usecache=True,cacheresponse=True):
        string = self.path + quote(self.cleanhtmlstring) + '.html'
        return self.request(path=string,usecache=usecache,cacheresponse=cacheresponse)

    def cleanhtml(self,usecache=True,cacheresponse=True):
        string = self.path + self.cleanhtmlstring + '.html'
        return self.request(path=string,usecache=usecache,cacheresponse=cacheresponse)
        
    def xssstandard(self,usecache=True,cacheresponse=True):
        xssstringa = self.path + self.xssstring + '.html'
        return self.request(path=xssstringa,usecache=usecache,cacheresponse=cacheresponse)
    
    def xssstandardencoded(self,usecache=True,cacheresponse=True):
        xssstringa = self.path + quote(self.xssstring) + '.html'
        return self.request(path=xssstringa,usecache=usecache,cacheresponse=cacheresponse)
    
    def cmddotexe(self,usecache=True,cacheresponse=True):
        # thanks j0e
        string = self.path + 'cmd.exe'
        return self.request(path=string,usecache=usecache,cacheresponse=cacheresponse)
    
    attacks = [cmddotexe,directorytraversal,xssstandard,xssstandardencoded]
    
    def genericdetect(self,usecache=True,cacheresponse=True):        
        reason = ''
        reasons = ['Blocking is being done at connection/packet level.',
                   'The server header is different when an attack is detected.',
                   'The server returned a different response code when a string trigged the blacklist.',
                   'It closed the connection for a normal request.',
                   'The connection header was scrambled.'
                   ]
        # test if response for a path containing html tags with known evil strings
        # gives a different response from another containing invalid html tags
        r = self.cleanhtml()
        if r is None:
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        cleanresponse,_tmp =r
        r = self.xssstandard()
        if r is None:            
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        xssresponse,_tmp = r
        if xssresponse.status != cleanresponse.status:
            self.log.info('Server returned a different response when a script tag was tried')            
            reason = reasons[2]
            reason += '\r\n'
            reason += 'Normal response code is "%s",' % cleanresponse.status
            reason += ' while the response code to an attack is "%s"' % xssresponse.status
            self.knowledge['generic']['reason'] = reason
            self.knowledge['generic']['found'] = True
            return True
        r = self.cleanhtmlencoded()
        cleanresponse,_tmp = r
        r = self.xssstandardencoded()
        if r is None:            
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        xssresponse,_tmp = r
        if xssresponse.status != cleanresponse.status:
            self.log.info('Server returned a different response when a script tag was tried')
            reason = reasons[2]
            reason += '\r\n'
            reason += 'Normal response code is "%s",' % cleanresponse.status
            reason += ' while the response code to an attack is "%s"' % xssresponse.status
            self.knowledge['generic']['reason'] = reason
            self.knowledge['generic']['found'] = True
            return True
        response, responsebody = self.normalrequest()
        normalserver = response.getheader('Server')
        for attack in self.attacks:        
            r = attack(self)              
            if r is None:                
                self.knowledge['generic']['reason'] = reasons[0]
                self.knowledge['generic']['found'] = True
                return True
            response, responsebody = r
            attackresponse_server = response.getheader('Server')
            if attackresponse_server:
                if attackresponse_server != normalserver:
                    self.log.info('Server header changed, WAF possibly detected')
                    self.log.debug('attack response: %s' % attackresponse_server)
                    self.log.debug('normal response: %s' % normalserver)
                    reason = reasons[1]
                    reason += '\r\nThe server header for a normal response is "%s",' % normalserver
                    reason += ' while the server header a response to an attack is "%s.",' % attackresponse_server
                    self.knowledge['generic']['reason'] = reason
                    self.knowledge['generic']['found'] = True
                    return True
        for attack in self.wafdetectionsprio:
            if self.wafdetections[attack](self) is None:
                self.knowledge['generic']['reason'] = reasons[0]
                self.knowledge['generic']['found'] = True
                return True
        for attack in self.attacks:
            r = attack(self)
            if r is None:                
                self.knowledge['generic']['reason'] = reasons[0]
                self.knowledge['generic']['found'] = True
                return True
            response, responsebody = r
            for h,v in response.getheaders():
                if scrambledheader(h):
                    self.knowledge['generic']['reason'] = reasons[4]
                    self.knowledge['generic']['found'] = True
                    return True
        return False

    def matchheader(self,headermatch,attack=False,ignorecase=True):
        import re
        detected = False
        header,match = headermatch
        if attack:
            requests = self.attacks
        else:
            requests = [self.normalrequest]
        for request in requests:            
            r = request(self)
            if r is None:                
                return
            response,responsebody = r
            headerval = response.getheader(header)
            if headerval:
                # set-cookie can have multiple headers, python gives it to us
                # concatinated with a comma
                if header == 'set-cookie':
                    headervals = headerval.split(', ')
                else:
                    headervals = [headerval]
                for headerval in headervals:
                    if ignorecase:
                        if re.match(match,headerval,re.IGNORECASE):
                            detected = True
                            break
                    else:
                        if re.match(match,headerval):
                            detected = True
                            break
                if detected:
                    break
        return detected

    def isbigip(self):
        return self.matchheader(('X-Cnection','^close$'), attack=True)
    
    def iswebknight(self):
        detected = False
        for attack in self.attacks:
            r = attack(self)
            if r is None:                
                return
            response, responsebody = r
            if response.status == 999:
                detected = True
                break
        return detected
        
    def ismodsecurity(self):
        detected = False
        for attack in self.attacks:
            r = attack(self)
            if r is None:                
                return
            response, responsebody = r
            if response.status == 501:
                detected = True
                break
        return detected
    
    def issecureiis(self):
        detected = False
        headers = dict()
        headers['Transfer-Encoding'] = 'z' * 1025
        r = self.normalrequest(headers=headers)
        if r is None:
            return 
        response,responsebody = r 
        if response.status == 404:
            detected = True
        return detected
    
    def matchcookie(self,match):
        """
        a convenience function which calls matchheader
        """
        return self.matchheader(('set-cookie',match))
    
    def isairlock(self):
        return self.matchcookie('^AL[_-]?(SESS|LB)=')
    
    def isbarracuda(self):
        return self.matchcookie('^barra_counter_session=')
    
    def isdenyall(self):
        if self.matchcookie('^sessioncookie='):
            return True
        for attack in self.attacks:
            r = attack(self)
            if r is None:
                return
            response, responsebody = r
            if response.status == 200:
                if response.reason == 'Condition Intercepted':
                    return True
        return False
    
    def isbeeware(self):
        detected = False
        r = self.xssstandard()
        if r is None:
            return
        response, responsebody = r
        if (response.status != 200) or (response.reason == 'Forbidden'):
            r = self.directorytraversal()
            if r is None:
                return
            response, responsebody = r
            if response.status == 403:
                if response.reason == "Forbidden":
                    detected = True
        return detected
        
    def isf5asm(self):
        return self.matchcookie('^TS[a-zA-Z0-9]{3,6}=')
    
    def isf5trafficshield(self):
        for hv in [['cookie','^ASINFO='],['server','F5-TrafficShield']]:            
            r = self.matchheader(hv)
            if r is None:
                return
            elif r:
                return r
        return False

    def isteros(self):
        return self.matchcookie('^st8id=')
    
    def isnetcontinuum(self):
        return self.matchcookie('^NCI__SessionId=')
    
    def isbinarysec(self):
        return self.matchheader(('server','BinarySec'))
    
    def ishyperguard(self):
        return self.matchcookie('^WODSESSION=')
    
    def isprofense(self):
        """
        Checks for server headers containing "profense"
        """
        return self.matchheader(('server','profense'))
        
    def isnetscaler(self):
        """
        First checks if a cookie associated with Netscaler is present,
        if not it will try to find if a "Cneonction" or "nnCoection" is returned
        for any of the attacks sent
        """
        if self.matchcookie('^ns_af='):
            return True        
        if self.matchheader(('Cneonction','close'),attack=True):
            return True
        if self.matchheader(('nnCoection','close'),attack=True):
            return True
        return False
    
    def isurlscan(self):
        detected = False
        testheaders = dict()
        testheaders['Translate'] = 'z'*10
        testheaders['If'] = 'z'*10
        testheaders['Lock-Token'] = 'z'*10
        testheaders['Transfer-Encoding'] = 'z'*10
        r = self.normalrequest()
        if r is None:
            return
        response,_tmp = r
        r = self.normalrequest(headers=testheaders)
        if r is None:
            return 
        response2,_tmp = r
        if response.status != response2.status:
            if response2.status == 404:
                detected = True
        return detected
    
    def iswebscurity(self):
        detected = False
        r = self.normalrequest()
        if r is None:
            return
        response,responsebody=r
        if response.status == 403:
            return detected
        newpath = self.path + '?nx=@@'
        r = self.request(path=newpath)
        if r is None:
            return 
        response,responsebody = r
        if response.status == 403:
            detected = True
        return detected
    
    def isdotdefender(self):
        return self.matchheader(['X-dotDefender-denied', '^1$'],attack=True)

    def isimperva(self):
        for attack in self.attacks:
            r = attack(self)
            if r is None:
                return
            response, responsebody = r
            if response.version == 10:
                return True
        return False
    
    def ismodsecuritypositive(self):
        import random
        detected = False
        self.normalrequest(usecache=False,cacheresponse=False)
        randomfn = self.path + str(random.randrange(1000,9999)) + '.html'
        r = self.request(path=randomfn)
        if r is None:
            return
        response,responsebody = r
        if response.status != 302:
            return False
        randomfnnull = randomfn+'%00'
        r = self.request(path=randomfnnull)
        if r is None:
            return
        response,responsebody = r
        if response.status == 404:
            detected = True
        return detected
    
    pdxdetections = dict()
    # easy ones
    pdxdetections['Profense'] = isprofense
    pdxdetections['ModSecurity'] = ismodsecurity
    pdxdetections['NetContinuum'] = isnetcontinuum
    pdxdetections['HyperGuard'] = ishyperguard
    pdxdetections['Barracuda'] = isbarracuda
    pdxdetections['Airlock'] = isairlock
    pdxdetections['BinarySec'] = isbinarysec
    pdxdetections['F5 Trafficshield'] = isf5trafficshield
    pdxdetections['F5 ASM'] = isf5asm
    pdxdetections['Teros'] = isteros
    pdxdetections['DenyALL'] = isdenyall
    pdxdetections['BIG-IP'] = isbigip
    pdxdetections['Citrix NetScaler'] = isnetscaler
    # lil bit more complex
    pdxdetections['webApp.secure'] = iswebscurity
    pdxdetections['WebKnight'] = iswebknight    
    pdxdetections['URLScan'] = isurlscan
    pdxdetections['SecureIIS'] = issecureiis
    pdxdetections['dotDefender'] = isdotdefender
    pdxdetections['BeeWare'] = isbeeware
    # pdxdetections['ModSecurity (positive model)'] = ismodsecuritypositive removed for now
    pdxdetections['Imperva'] = isimperva
    pdxdetectionsprio = ['Profense','NetContinuum',                         
                         'Barracuda','HyperGuard','BinarySec','Teros',
                         'F5 Trafficshield','F5 ASM','Airlock','Citrix NetScaler',
                         'ModSecurity', 'DenyALL',
                         'dotDefender','webApp.secure', # removed for now 'ModSecurity (positive model)',                         
                         'BIG-IP','URLScan','WebKnight', 
                         'SecureIIS','BeeWare','Imperva']
    
    def identpdx(self,findall=False):
        detected = list()
        for pdxvendor in self.pdxdetectionsprio:
            self.log.info('Checking for %s' % pdxvendor)
            if self.pdxdetections[pdxvendor](self):
                detected.append(pdxvendor)
                if not findall:
                    break
        self.knowledge['pdxname'] = detected
        return detected

def calclogginglevel(verbosity):
    default = 40 # errors are printed out
    level = default - (verbosity*10)
    if level < 0:
        level = 0
    return level

class paradox_api:
    def __init__(self):
        self.cache = dict()
        
    def vendordetect(self,url,findall=False):            
        if self.cache.has_key(url):
            Paradox = self.cache[url]
        else:
            r = oururlparse(url)
            if r is None:
                return ['']
            (hostname,port,path,query,ssl) = r
            Paradox = Paradox(target=hostname,port=80,path=path,ssl=ssl)
            self.cache[url] = Paradox
        return Paradox.identpdx(findall=findall)
    
    def genericdetect(self,url):            
        if self.cache.has_key(url):
            Paradox = self.cache[url]
        else:
            r = oururlparse(url)
            if r is None:
                return {}
            (hostname,port,path,query,ssl) = r
            Paradox = Paradox(target=hostname,port=80,path=path,ssl=ssl)
            self.cache[url] = Paradox
        Paradox.genericdetect()
        return Paradox.knowledge['generic']
        
    def alltests(self,url,findall=False):
        if self.cache.has_key(url):
            Paradox = self.cache[url]
        else:
            r = oururlparse(url)
            if r is None:
                return {}
            (hostname,port,path,query,ssl)  = r
            Paradox = Paradox(target=hostname,port=80,path=path,ssl=ssl)
            self.cache[url] = Paradox
        Paradox.identpdx(findall=findall)
        if (len(Paradox.knowledge['pdxname']) == 0) or (findall):
            Paradox.genericdetect()
        return Paradox.knowledge




def xmlrpc_interface(bindaddr=('localhost',8001)):
    from SimpleXMLRPCServer import SimpleXMLRPCServer
    from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
    
    class RequestHandler(SimpleXMLRPCRequestHandler):
        rpc_paths = ('/RPC2',)
    
        
    server = SimpleXMLRPCServer(bindaddr,
                            requestHandler=RequestHandler)
    server.register_introspection_functions()
    server.register_instance(paradox_api())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print "bye!"
        return




def main():
    print lackofart
    parser = OptionParser(usage="""%prog url1 [url2 [url3 ... ]]\r\nexample: %prog http://www.google.com/""")
    parser.add_option('-v','--verbose',action='count', dest='verbose', default=0,
                      help="enable verbosity - multiple -v options increase verbosity")
    parser.add_option('-a','--findall',action='store_true', dest='findall', default=False,
                      help="Find all Paradoxs, do not stop testing on the first one")
    parser.add_option('-r','--disableredirect',action='store_false',dest='followredirect',
                      default=True, help='Do not follow redirections given by 3xx responses')
    parser.add_option('-t','--test',dest='test',
                      help='Test for one specific Paradox')
    parser.add_option('-l','--list',dest='list', action='store_true',
                      default=False,help='List all Paradoxs that we are able to detect')
    parser.add_option('--xmlrpc',dest='xmlrpc', action='store_true',
                      default=False,help='Switch on the XML-RPC interface instead of CUI')
    parser.add_option('--xmlrpcport',dest='xmlrpcport', type='int',
                      default=8001,help='Specify an alternative port to listen on, default 8001')
    parser.add_option('--version','-V',dest='version', action='store_true',
                      default=False,help='Print out the version')
    options,args = parser.parse_args()
    logging.basicConfig(level=calclogginglevel(options.verbose))
    log = logging.getLogger()
    if options.list:
        print "Can test for these Paradoxs:\r\n"
        attacker = Paradox(None)        
        print '\r\n'.join(attacker.pdxdetectionsprio)
        return
    if options.version:
        print 'Paradox version %s' % __version__
        return
    elif options.xmlrpc:
        print "Starting XML-RPC interface"
        xmlrpc_interface(bindaddr=('localhost',options.xmlrpcport))
        return
    if len(args) == 0:
        parser.error("we need a target site")
    targets = args
    for target in targets:
        print "Checking %s" % target
        pret = oururlparse(target)
        if pret is None:
            log.critical('The url %s is not well formed' % target)
            sys.exit(1)
        (hostname,port,path,query,ssl) = pret
        log.info('starting Paradox on %s' % target)
        attacker = Paradox(hostname,port=port,ssl=ssl,
                           debuglevel=options.verbose,path=path,
                           followredirect=options.followredirect)
        if attacker.normalrequest() is None:
            log.error('Site %s appears to be down' % target)
            sys.exit(1)
        if options.test:
            if attacker.pdxdetections.has_key(options.test):
                pdx = attacker.pdxdetections[options.test](attacker)
                if pdx:
                    print "The site %s is behind a %s" % (target, options.test)
                else:
                    print "Paradox %s was not detected on %s" % (options.test,target)
            else:
                print "Paradox %s was not found in our list\r\nUse the --list option to see what is available" % options.test
            return
        pdx = attacker.identpdx(options.findall)
        log.info('Ident Paradox: %s' % pdx)
        if len(pdx) > 0:
            print 'The site %s is behind a %s' % (target, ' and/or '.join( pdx))
        if (options.findall) or len(pdx) == 0:
            print 'Generic Detection results:'          
            if attacker.genericdetect():                
                log.info('Generic Detection: %s' % attacker.knowledge['generic']['reason'])                    
                print 'The site %s seems to be behind a Paradox ' % target
                print 'Reason: %s' % attacker.knowledge['generic']['reason']
            else:
                print 'No Paradox detected by the generic detection'
        print 'Number of requests: %s' % attacker.requestnumber

if __name__ == '__main__':
    if sys.hexversion < 0x2040000:
        sys.stderr.write('Your version of python is way too old .. please update to 2.4 or later\r\n')        
    main()
