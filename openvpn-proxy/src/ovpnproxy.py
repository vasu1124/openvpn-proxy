"""
Usage 'ovpnproxy'

OpenVPN Intercepting Multiplexer/Proxy

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
from logging.handlers import RotatingFileHandler

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
    msgFragment = False
    msgOpcode = -1

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
        self.msgOpcode = -1
        
        if data.__len__() < struct.calcsize('>HBQB'):
            return []
        
        PacketLength, OpcodeKey, SessionID, MPIDArrayLength = struct.unpack('>HBQB', data[:struct.calcsize('>HBQB')])
        Opcode = (OpcodeKey & P_OPCODE_MASK) >> 3
        Key = OpcodeKey    & P_KEY_ID_MASK
        Logger.log(DDDEBUG, 'Opcode %d Key %d SessionID %d PacketLength %d MPIDArrayLength %d' % (Opcode, Key, SessionID, PacketLength, MPIDArrayLength))
        data = data[struct.calcsize('>HBQB'):]
        msgfrag = data[:PacketLength]
        PacketLength -= struct.calcsize('>BQB')
        data = data[PacketLength:]
        
        if Opcode == P_CONTROL_HARD_RESET_CLIENT_V1:
            self.msgOpcode = P_CONTROL_HARD_RESET_CLIENT_V1
            Logger.log(DDEBUG, 'P_CONTROL_HARD_RESET_CLIENT_V1')
        elif Opcode == P_CONTROL_HARD_RESET_SERVER_V1:
            self.msgOpcode = P_CONTROL_HARD_RESET_SERVER_V1
            Logger.log(DDEBUG, 'P_CONTROL_HARD_RESET_SERVER_V1')
        elif Opcode == P_CONTROL_SOFT_RESET_V1:
            self.msgOpcode = P_CONTROL_SOFT_RESET_V1
            Logger.log(DDEBUG, 'P_CONTROL_SOFT_RESET_V1')
        elif Opcode == P_DATA_V1:
            self.msgOpcode = P_DATA_V1
            Logger.log(DDEBUG, 'P_DATA_V1')
        elif Opcode == P_CONTROL_HARD_RESET_CLIENT_V2:
            self.msgOpcode = P_CONTROL_HARD_RESET_CLIENT_V2
            Logger.log(DDEBUG, 'P_CONTROL_HARD_RESET_CLIENT_V2')
        elif Opcode == P_ACK_V1:
            self.msgOpcode = P_ACK_V1
            Logger.log(DDEBUG, 'P_ACK_V1')
        elif Opcode == P_CONTROL_V1:
            self.msgOpcode = P_CONTROL_V1   
                     
            if MPIDArrayLength == 0: 
                MPID, = struct.unpack('>L', msgfrag[:struct.calcsize('>L')])  # @UnusedVariable
                msgfrag = msgfrag[struct.calcsize('>L'):]
                PacketLength -= struct.calcsize('>L')
                Logger.log(DDDEBUG, 'MPID %d' % (MPID, ))
            elif MPIDArrayLength >= 1:
                msgfrag = msgfrag[struct.calcsize('>L')*MPIDArrayLength:] # jump over MPIDA-Elements
                RemoteSessionID, MPID = struct.unpack('>QL', msgfrag[:struct.calcsize('>QL')])  # @UnusedVariable
                msgfrag = msgfrag[struct.calcsize('>QL'):]
                PacketLength -= struct.calcsize('>QL') + struct.calcsize('>L')*MPIDArrayLength
                Logger.log(DDDEBUG, 'MPID %d RemoteSessionID %d' % (MPID, RemoteSessionID))
            
            if PacketLength == 100:
                if not self.msgFragment:         
                    self.msgFragment = True
                    self.msg = msgfrag[:PacketLength]
                    Logger.log(DDEBUG, 'frag init P_CONTROL_V1')
                else:
                    self.msg += msgfrag[:PacketLength]
                    Logger.log(DDEBUG, 'frag P_CONTROL_V1')
            elif self.msgFragment:
                    self.msgFragment = False
                    self.msg += msgfrag[:PacketLength]                                        
                    Logger.log(DDEBUG, 'fg P_CONTROL_V1')
            else:
                    self.msgFragment = False
                    self.msg = msgfrag[:PacketLength]                                        
                    Logger.log(DDEBUG, 'P_CONTROL_V1')
                    
        elif Opcode == P_CONTROL_HARD_RESET_SERVER_V2:
            self.msgOpcode = P_CONTROL_HARD_RESET_SERVER_V2            
            Logger.log(DDEBUG, 'P_CONTROL_HARD_RESET_SERVER_V2')  
        else:
            data = []

        return data

    def parseOpenVPN(self, data):
        while True:
            data = self.parseOpenVPNfrag(data)
            if data.__len__() == 0 : break
        return self.msgOpcode
    
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
                if e.errno == 9 or \
                   e.errno == 10054 or \
                   e.errno==104:
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
                                
#                   consume message                           
                    if dtsP.msgOpcode == -1:
                        #no OpenVPN protocol
                        Logger.info('No OpenVPN protocol!')
                        return
                    if dtsP.msgOpcode == P_CONTROL_V1 and not dtsP.msgFragment:
#                        dtsP.msgOpcode = -1
                        tls = dtsP.parseTSLv1(dtsP.msg)                    
                        for t in tls:
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
                                        source2Sink.start()
                                        Thread.setName(sink2Source, '%s<-%s' % (self.source.getpeername(), self.sink.getpeername()))
                                        sink2Source.start()
                                        return

                    if dataToServer: 
                        Logger.log(DDDEBUG, '->\n' + hexdump(dataToServer, ' ', 40))
                        Logger.log(DDEBUG, 'Sending Data to %s' % (self.sink.getpeername(),) )
                        self.sink.send( dataToServer )

                    dataFromServer = None
                    
                    try:
                        dataFromServer = self.sink.recv( 9000 )
                    except socket.timeout:
                        pass
                    
                    if dataFromServer:
                        dtcP.parseOpenVPN(dataFromServer)

#                   consume message
                        
                    if dataFromServer:                        
                        Logger.log(DDDEBUG, '<-\n' + hexdump(dataFromServer, ' ', 40))
                        Logger.log(DDEBUG, 'Sending Data to %s' % (self.source.getpeername(),) )
                        self.source.send( dataFromServer )
                
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
        maxBytes = Config.getint('Logging', 'maxBytes')
        backupCount = Config.getint('Logging', 'backupCount')
        loghandler = RotatingFileHandler(logfile, maxBytes=maxBytes, backupCount=backupCount)
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
      
