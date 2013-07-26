"""
Usage 'ovpnproxy'

OpenVPN Intercepting Multiplexer/Proxy 
============================================================
Copyright (C) 2013 Vasu Chandrasekhara. All Rights Reserved.
============================================================

Keep an ovpnproxy.cfg file with the following content:
[Logging]
#Optionally, write to a rotating logfile:
# file = ovpnproxy.log
# maxBytes = 102400
# backupCount = 5
loglevel = DEBUG
#    The logging levels, in decreasing order of importance, are:
# CRITICAL = 50
# FATAL = CRITICAL
# ERROR = 40
# WARNING = 30
# WARN = WARNING
# INFO = 20
# DEBUG = 10
# DDEBUG = 5
# DDDEBUG = 4

[proxy]
# listen for incoming requests here 
ip = 0.0.0.0
port = 9999

[sinkvpn]
# this is your default vpn sink
ip = 172.19.136.144
port = 443 

# the follwoing sections represent the multiplexed VPN endpoints, 
# based on the subject.CN in the client certificate
# the subject.CN is specified as [section header]

[client1]
ip = 172.19.139.156
port = 443 

[client2]
ip = 172.19.139.157
port = 443 

# the config file is dynamic
============================================================
Copyright (C) 2013 Vasu Chandrasekhara. All Rights Reserved.
============================================================
"""

import socket
from threading import Thread
import struct 
from M2Crypto import X509
import ConfigParser
import logging


# OPVPN Opcodes 
P_CONTROL_HARD_RESET_CLIENT_V1  = 1
P_CONTROL_HARD_RESET_SERVER_V1  = 2
P_CONTROL_SOFT_RESET_V1         = 3
P_CONTROL_V1                    = 4
P_ACK_V1                        = 5
P_DATA_V1                       = 6
P_CONTROL_HARD_RESET_CLIENT_V2  = 7
P_CONTROL_HARD_RESET_SERVER_V2  = 8
# packet opcode and key-id are combined in one byte
P_OPCODE_MASK = 0xF8 # packet opcode (high 5 bits) 
P_KEY_ID_MASK = 0x07 # key-id (low 3 bits) 

DDEBUG = 5
DDDEBUG = 4
Logger = logging.getLogger("OVPN-Proxy")

def hexdump( chars, sep, width ):
    ret = ""
    if width > chars.__len__(): width=chars.__len__()
    while chars:
        line = chars[:width]
        chars = chars[width:]
#        line = line.ljust( width, '\000' )
        ret += "%s%s%s" % ( sep.join( "%02x" % ord(c) for c in line ), sep, quotechars( line )) + "\n"
    return ret

def quotechars( chars ):
    return ''.join( ['.', c][c.isalnum()] for c in chars )

class OVPNParser():
    msg = ''
    msgfrg = False
    msgflag = -1

    def parseTSLv1Handshake22Certificates(self, data):
        certs = []
        data = data[3:] # overall length
        while True:
            data = ''.join([chr(0), data])
            Length, = struct.unpack('>L', data[:struct.calcsize('>L')])
            Protocol = data[struct.calcsize('>L'):Length+struct.calcsize('>L')]
            data = data[Length+struct.calcsize('>L'):]                   
            certs.append([Length, Protocol])
            if data.__len__() == 0: break
        return certs

    def parseTSLv1Handshake(self, data):
        ContentType, = struct.unpack('>B', data[:struct.calcsize('>B')])
        data = ''.join([chr(0), data[1:]])
        Length, = struct.unpack('>L', data[:struct.calcsize('>L')])
        Protocol = data[struct.calcsize('>L'):Length+struct.calcsize('>L')]            
        hs = [ContentType, Length, Protocol]
        return hs
    
    def parseTSLv1(self, data):
        ttls = []
        while True:
            ContentType, Version, Length = struct.unpack('>BHH', data[:struct.calcsize('>BHH')])
            data = data[struct.calcsize('>BHH'):]
            Protocol = data[:Length]            
            data = data[Length:]
            ttls.append([ContentType, Version, Length, Protocol])
            if data.__len__() == 0: break
        return ttls
        
    def parseOpenVPNfrag(self, data):
        PacketLength, OpcodeKey, SessionID, MPIDArrayLength = struct.unpack('>HBQB', data[:struct.calcsize('>HBQB')])
        Opcode = (OpcodeKey & P_OPCODE_MASK) >> 3
        Key = OpcodeKey    & P_KEY_ID_MASK
        Logger.log(DDDEBUG, 'Opcode %d Key %d SessionID %d PacketLength %d MPIDArrayLength %d' % (Opcode, Key, SessionID, PacketLength, MPIDArrayLength))
        data = data[struct.calcsize('>HBQB'):]
        PacketLength -= struct.calcsize('>BQB')
        if Opcode == P_CONTROL_HARD_RESET_CLIENT_V1:
            data = data[PacketLength:]
            Logger.log(DDEBUG, 'P_CONTROL_HARD_RESET_CLIENT_V1')
        elif Opcode == P_CONTROL_HARD_RESET_SERVER_V1:
            data = data[PacketLength:]
            Logger.log(DDEBUG, 'P_CONTROL_HARD_RESET_SERVER_V1')
        elif Opcode == P_CONTROL_SOFT_RESET_V1:
            data = data[PacketLength:]
            Logger.log(DDEBUG, 'P_CONTROL_SOFT_RESET_V1')
        elif Opcode == P_DATA_V1:
            data = data[PacketLength:]
            Logger.log(DDEBUG, 'P_DATA_V1')
        elif Opcode == P_CONTROL_HARD_RESET_CLIENT_V2:
            data = data[PacketLength:]
            Logger.log(DDEBUG, 'P_CONTROL_HARD_RESET_CLIENT_V2')
        elif Opcode == P_ACK_V1:
            data = data[PacketLength:]
            Logger.log(DDEBUG, 'P_ACK_V1')
        elif Opcode == P_CONTROL_V1:
            if MPIDArrayLength == 0: 
                MPID, = struct.unpack('>L', data[:struct.calcsize('>L')])  # @UnusedVariable
                data = data[struct.calcsize('>L'):]
                PacketLength -= struct.calcsize('>L')
                Logger.log(DDDEBUG, 'MPID %d' % (MPID, ))
            elif MPIDArrayLength >= 1:
                data = data[struct.calcsize('>L')*MPIDArrayLength:] # jump over MPIDA-Elements
                RemoteSessionID, MPID = struct.unpack('>QL', data[:struct.calcsize('>QL')])  # @UnusedVariable
                data = data[struct.calcsize('>QL'):]
                PacketLength -= struct.calcsize('>QL') + struct.calcsize('>L')*MPIDArrayLength
                Logger.log(DDDEBUG, 'MPID %d RemoteSessionID %d' % (MPID, RemoteSessionID))
            
            msgfrag = data[:PacketLength]
            data = data[PacketLength:]
            if msgfrag.__len__() == 100:
                if not self.msgfrg:         
                    self.msgfrg = True
                    self.msg = msgfrag
                    Logger.log(DDEBUG, 'frag init P_CONTROL_V1')
                else:
                    self.msg += msgfrag
                    Logger.log(DDEBUG, 'frag P_CONTROL_V1')
            elif self.msgfrg:
                    self.msgfrg = False
                    self.msg += msgfrag                                        
                    self.msgflag = P_CONTROL_V1
                    Logger.log(DDEBUG, 'fg P_CONTROL_V1')
            else:
                    self.msgfrg = False
                    self.msg = msgfrag                                        
                    self.msgflag = P_CONTROL_V1
                    Logger.log(DDEBUG, 'P_CONTROL_V1')
        elif Opcode == P_CONTROL_HARD_RESET_SERVER_V2:
            data = data[PacketLength:]
            Logger.log(DDEBUG, 'P_CONTROL_HARD_RESET_SERVER_V2')  
        else:
            data = []
        return data

    def parseOpenVPN(self, data):
        while True:
            data = self.parseOpenVPNfrag(data)
            if data.__len__() == 0 : break
        return self.msgflag
    
class PipeThread( Thread ):   

    pipes = []    
    skip = 0
    dtsP = OVPNParser()
    
    def __init__(self, source, sink, skip=0):
        Thread.__init__( self )
        self.source = source
        self.sink = sink
        self.skip = skip
        
        Logger.debug( 'Creating new pipe thread %s->%s' % (source.getpeername(), sink.getpeername()))
        PipeThread.pipes.append( self )
        
    def run( self):
        Logger.info( '... starting' )
        while True:
            try:
                if self.skip>0:
                    self.skip -= 1
                    Logger.log(DDEBUG, 'Skipping msg')
                else:                                                
                    data = self.source.recv( 9000 )
                    if not data: break
                    Logger.log(DDDEBUG, '\n' + hexdump(data, ' ', 40))                
#                   send data
                    self.sink.send( data )
                    
                    if Logger.getEffectiveLevel() == DDEBUG:
                        self.dtsP.parseOpenVPN(data)
                                        
            except IOError as e:
                if e.errno == 9 or e.errno == 10054:
                    pass
                else:
                    Logger.exception('Caught IOError in main loop')
                break
            except:
                Logger.exception('Caught Exception in main loop')
                break

        Logger.debug( '... terminating' )
        self.source.close()
        self.sink.close()
        PipeThread.pipes.remove( self )        

class PipeIntercept( PipeThread ):   
        
    def run( self):
        Logger.info( '::: starting' )

        self.source.settimeout(0.1)
        self.sink.settimeout(0.1)
        dtsP = OVPNParser()
        dtcP = OVPNParser()
        try:  
            while True:
                try:
                    dataToServer = None
                    try:                
                        dataToServer = self.source.recv( 9000 )
                    except socket.timeout:
                        pass
                
                    if dataToServer:
                        dtsP.parseOpenVPN(dataToServer)
                                
#                   consume final message                       
                    if dtsP.msgflag == P_CONTROL_V1:
                        dtsP.msgflag = -1
                        tls = dtsP.parseTSLv1(dtsP.msg)                    
                        for t in tls:
#                            print t
                            if t[0] == 22: #handshake
                                hs = dtsP.parseTSLv1Handshake(t[3])
                                if hs[0] == 11: #Certificate
                                    # found what we wanted, initiate handover
                                    certs = dtsP.parseTSLv1Handshake22Certificates(hs[2])
                                    for c in certs:
                                        x509 = X509.load_cert_string(c[1], X509.FORMAT_DER)
                                        subject = x509.get_subject()
                                        Logger.info('Identified incoming certificate: (CN=%s O=%s)' % (subject.CN, subject.O ))
                                        #dynamically reread the config file
                                        lConfig = ConfigParser.ConfigParser()
                                        lConfig.read('ovpnproxy.cfg')
                                        try:
                                            sinkhost  = lConfig.get(subject.CN, 'ip')
                                            sinkport  = lConfig.getint(subject.CN, 'port')
                                            if self.sink.getpeername()[0] <> sinkhost or self.sink.getpeername()[1] <> sinkport:
                                                Logger.info('Identified forward: %s, %s' % (sinkhost, sinkport ))
                                                self.sink.close()
                                                self.sink = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
                                                self.sink.connect((sinkhost, sinkport))
                                                skip=0                                         
                                            else:
                                                Logger.info('Keeping forward: %s, %s' % (sinkhost, sinkport))
                                                skip=0
                                        except:
                                            skip=0
                                            Logger.info('No Config for certificate found! Keeping forward: %s ' % (self.sink.getpeername(), ))
                                            
                                            
                                        self.source.setblocking(True)
                                        self.sink.setblocking(True)
                                        source2Sink = PipeThread(self.source, self.sink)
                                        sink2Source = PipeThread(self.sink, self.source, skip=skip)                                            
                                        Thread.setName(source2Sink, '%s->%s' % (self.source.getpeername(), self.sink.getpeername()))
                                        Thread.setName(sink2Source, '%s<-%s' % (self.source.getpeername(), self.sink.getpeername()))
                                        source2Sink.start()
                                        sink2Source.start()
                                        return

#                   message consumed                               
                    if not dtsP.msgfrg:
                        dtsP.msg = ''                    

                    if dataToServer: 
                        Logger.log(DDDEBUG, '\n' + hexdump(dataToServer, ' ', 40))
                        Logger.log(DDEBUG, 'Sending to %s' % (self.sink.getpeername(),) )
                        self.sink.send( dataToServer )

                    dataFromServer = None
                    
                    try:
                        dataFromServer = self.sink.recv( 9000 )
                    except socket.timeout:
                        pass
                    
                    if dataFromServer: self.source.send( dataFromServer )
                    if dataFromServer:
                        dtcP.parseOpenVPN(dataFromServer)

#                   message consumed                               
                    if not dtcP.msgfrg:
                        dtcP.msg = ''                    
                
                except IOError as e:
                    if e.errno == 9 or e.errno == 10054:
                        break
                    else:
                        Logger.exception('Caught IOError in main loop')
                        break
                except:
                    Logger.exception('Caught Exception in main loop')
                    break
        finally:
            Logger.info( '::: terminating' )
            PipeThread.pipes.remove( self )        


class OVPNProxy( Thread ):
    def __init__( self, ip, port, newhost, newport ):
        Thread.__init__( self )
        self.newhost = newhost
        self.newport = newport
        self.sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.sock.bind(( ip, port ))
        self.sock.listen(5)
        Logger.info( 'Redirecting: %s->(%s, %s)' % ( self.sock.getsockname(), newhost, newport ))
        Thread.setName(self, 'Listening %s' % ( self.sock.getsockname(), ) )
    
    def run( self ):
        while True:
            incoming, address = self.sock.accept()
            Logger.info( 'Creating new session for %s %s ' % address )
            fwd = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            fwd.connect(( self.newhost, self.newport ))
            pt = PipeIntercept(incoming, fwd)
            Thread.setName(pt, '%s<->%s' % (incoming.getpeername(), fwd.getpeername()))
            pt.start()
            Logger.debug( '%s pipes active' % len( PipeThread.pipes ))
            
if __name__ == '__main__':
    logging.addLevelName(DDEBUG, "DDEBUG")
    logging.addLevelName(DDDEBUG, "DDDEBUG")
    
    loghandler = logging.StreamHandler()
        
    Config = ConfigParser.ConfigParser()
    Config.read('ovpnproxy.cfg')
    
    try:
        logfile  = Config.get('Logging', 'file', raw=False)
        maxBytes = Config.getint('Logging', 'maxBytes', raw=False)
        backupCount = Config.getint('Logging', 'backupCount', raw=False)
        loghandler = logging.handlers.RotatingFileHandler(logfile, maxBytes=maxBytes, backupCount=backupCount)
    except ConfigParser.Error:
        pass

    loglevel = Config.get('Logging', 'loglevel')
    Logger.setLevel(loglevel)

    formatter = logging.Formatter('%(asctime)s - %(levelname)8s - %(module)10s:%(lineno)4d:%(threadName)52s(%(thread)5d) - %(message)s')
    loghandler.setFormatter(formatter)
    Logger.addHandler(loghandler)
    Logger.info('Starting OVPN Proxy')

    proxyip = Config.get('proxy', 'ip')
    proxyport = Config.getint('proxy', 'port')
    sinkhost  = Config.get('sinkvpn', 'ip')
    sinkport  = Config.getint('sinkvpn', 'port')
    
    Logger.debug('Local port: %d', proxyport)
    Logger.debug('Sink = (%s, %d)', sinkhost, sinkport)
    OVPNProxy( proxyip, proxyport, sinkhost, sinkport ).start()
      