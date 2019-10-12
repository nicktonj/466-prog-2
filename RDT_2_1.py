import Network_2_1 as Network
import argparse
from time import sleep
import hashlib

# This is a Packet class
class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10 # packet sequence number
    ack_S_length = 2 # acknowledge flag. Only needs one bit, but put two to keep things even
    length_S_length = 10 # total length of packet
    ## length of md5 checksum in hex
    checksum_length = 32 

    ### Packet order ###
    # length, seq_num, ack, checksum, msg #
    ### End packet order ### 
    def __init__(self, seq_num, msg_S='', ack=1):
        self.seq_num = seq_num
        self.msg_S = msg_S # defaults to empty string since ACK packets don't need data
        self.ack = ack # defaults to one since the base assumption is that the packet makes it to its destination
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            # raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
            # print('CORRUPT')
            return self(0, ack=0) # returns a NAK packet, sequence number won't matter since it's a NAK anyway
        # extract the fields
        seq_num = int(byte_S[
            Packet.length_S_length : Packet.length_S_length + Packet.seq_num_S_length
        ]) # end of packet length to end of sequence number
        # print("OK > seq_num:", seq_num)
        ack = int(byte_S[
            Packet.length_S_length + Packet.seq_num_S_length : Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length
        ]) # end of sequence number to end of ACK flag
        msg_S = byte_S[
            Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length+Packet.checksum_length :
        ] # end of checksum to end of packet
        return self(seq_num, msg_S, ack)
        
        
    def get_byte_S(self):
        # print("\nCreating packet...")
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # print("OK > seq_num:", str(int(seq_num_S)))
        # convert ACK flag to a byte field of ack_S_length bytes
        ack_S = str(self.ack).zfill(self.ack_S_length)
        # print("ack_S:", str(int(ack_S)))
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + len(ack_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        # print("length_S:", str(int(length_S)))
        # print("msg_S:", str(self.msg_S))
        # compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+ack_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # print("\nchecksum:", checksum_S, "\n")
        # return as a string
        return length_S + seq_num_S + ack_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        # print("\nChecking for corruption...")
        # extract the fields
        length_S = byte_S[
            0 : Packet.length_S_length
        ] # beginning of packet to end of packet length
        # print("length:", str(length_S))
        seq_num_S = byte_S[
            Packet.length_S_length : Packet.length_S_length + Packet.seq_num_S_length
        ] # end of packet length to end of sequence number
        ack_S = byte_S[
            Packet.length_S_length + Packet.seq_num_S_length : Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length
        ] # end of sequence number to end of ACK flag
        # print("ack:", str(ack_S))
        checksum_S = byte_S[
            Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length : Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length + Packet.checksum_length
        ] # end of ACK flag to end of checksum
        # print("checksum:", str(checksum_S))
        msg_S = byte_S[
            Packet.length_S_length + Packet.seq_num_S_length + Packet.ack_S_length + Packet.checksum_length :
        ] # end of checksum to end of packet 
        # print("msg:", str(msg_S))

        # compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+ack_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        '''
        if checksum_S != computed_checksum_S:
            print("\nCORRUPTION DETECTED")
            # print("Checksum:", checksum_S)
            # print("Computed Checksum:", computed_checksum_S, "\n")
            print("CORRUPT > seq_num:", str(seq_num_S))
        else:
            print("No corruption found.")
        '''
        return checksum_S != computed_checksum_S
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 0
    ## buffer of bytes read from network
    byte_buffer = '' 

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()

    def flip_seq_num(self):
        '''
        Flip the sequence number
        '''
        self.seq_num = 1 if self.seq_num == 0 else 0
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
    
    def rdt_2_1_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        print("Sending packet with seq_num =", p.seq_num)
        self.network.udt_send(p.get_byte_S())
        while self.seq_num == p.seq_num:
            byte_S = self.network.udt_receive()
            self.byte_buffer += byte_S
            if len(self.byte_buffer) < Packet.length_S_length:
                continue
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                continue
            p_ack = Packet.from_byte_S(self.byte_buffer[0:length])
            print("Received ACK =", p_ack.ack, "packet with seq_num =", p_ack.seq_num)
            self.byte_buffer = self.byte_buffer[length:]
            if p_ack.ack == 1 and p_ack.seq_num == self.seq_num:
                self.flip_seq_num()
                break
            else:
                print("Resending packet with seq_num =", p.seq_num)
                self.network.udt_send(p.get_byte_S())
        
    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        while True:
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S # not enough bytes to read packet length
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S # not enough bytes to read the whole packet
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            print("Received packet with seq_num =", p.seq_num)
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            print("Sending ACK for packet with seq_num = ", p.seq_num)
            self.network.udt_send(Packet(p.seq_num, ack=p.ack).get_byte_S())
            self.byte_buffer = self.byte_buffer[length:]
            if p.ack == 0 or (p.ack == 1 and p.seq_num != self.seq_num):
                byte_S = self.network.udt_receive()
    
    def rdt_3_0_send(self, msg_S):
        pass
        
    def rdt_3_0_receive(self):
        pass
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        
