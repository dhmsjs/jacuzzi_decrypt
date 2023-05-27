""" This module decrypts a Jacuzzi/Sundance "encrypted" message packet. """

def decrypt(packet: bytearray) -> bytearray:
    """ Returns a decrypted version of type "C4" panel status and type
    "CA" LED status message packets sent by "encrypted" control boards
    for Jacuzzi and Sundance spas. 

    Also updates the packet checksum byte so that any decrypted packet
    is still a vald message packet.

    Returns all other message packet types unchanged.

    The encryption algorithm used by Jacuzzi and Sundance is a type of
    "XOR Cipher" where each byte of the message data is XORed with the
    corresponding byte of an equal-length cipher string. In this case
    the bytes of the cipher string are just a decreasing sequence derived
    from the length of the message data.  

    In addition the encrypted packet includes an extra prefix byte which
    is used to form a constant value that is also XORed with each byte
    of the message data.  

    As is typical with XOR cipher encryption, you the same algorithm will
    both encrypt and decrypt a nessage. Thus you can also call decrypt()
    to encrypt type CC command messages before sending them to the spa
    controller.

    Typical encrypted C4 packet:
    byte #:    000102030405 060708 09101112 13141516 17181920 21222324 25262728 29303132 33343536 37 3839
    encrypted: 7e26ffafc41f 151b1a 1516a6ec 16107310 2d0c470b 68080a1d 05012206 b0000368 673c3f3e 39 937e
    decrypted: 7e26ffafc41f 0d0000 080ab9f2 07006002 3818501d 61000117 080d2d08 b100006a 62383838 00 8a7e
    """
    # Quit if the packet is too short
    if len(packet) < 7:
        return packet
    
    # Encrypted packets have an extra byte that we use to form the first key value
    packet_type = packet[4]
    if packet_type == 0xc4:
        key1 = packet[5] ^ 0x19
    elif packet_type == 0xca:
        key1 = packet[5] ^ 0x59
    elif packet_type == 0xcc:
        key1 = packet[5] ^ 0xde
    else:
        # Done if not an encrypted message type
        return packet
 
    # The second key value forms a cipher string which is a string of the same 
    # length as the encrypted data, and whose byte values are each decremented by
    # one from the previous, modulo 64.
    HEADER_LENGTH = 5
    packet_length = packet[1]
    key2 = packet_length - HEADER_LENGTH - 2

    # Just in case the packet we were given is an immutable "bytes" array
    # we will convert it to a (mutable) bytearray type.
    packet = bytearray(packet)

    # Apply both keys to each encrypted value and save the decrypted result
    # back into the original packet.
    for i in range(6, packet_length):
      key2 = (key2 - 1) % 64
      packet[i] = packet[i] ^ key1 ^ key2

    # Calculate a new checksum over entire decrypted packet and save it as
    # the new packet checksum.
    packet[-2] = balboa_calc_cs(packet[1:packet_length], packet_length - 1)

    return packet

# Unit testing support
if __name__ == "__main__":

    import sys # Only for access to command line parameters

    def balboa_calc_cs(data, length):
        """ Calculate the checksum byte for a balboa message """
        crc = 0xB5
        for cur in range(length):
            for i in range(8):
                bit = crc & 0x80
                crc = ((crc << 1) & 0xFF) | ((data[cur] >> (7 - i)) & 0x01)
                if bit:
                    crc = crc ^ 0x07
            crc &= 0xFF
        for i in range(8):
            bit = crc & 0x80
            crc = (crc << 1) & 0xFF
            if bit:
                crc ^= 0x07
        return crc ^ 0x02

    try:
        hextext = sys.argv[1]
    except:
        hextext = "7e26ffafc4a2aba6a7a8ad0251abadc8ad90b122b6d3b5b7a0b8bc92bb14bdbedee681828384f07e"

    # Force the data to be an immutable array just for unit testing
    data = bytes.fromhex(hextext)

    print('   Packet: {}'.format(data.hex()))
    data = decrypt(data)
    print('Decrypted: {}'.format(data.hex()))
    
    length = data[1]
    checksum = balboa_calc_cs(data[1:length], length - 1)
    if checksum == data[-2]:
        print("Checksum okay")
    else:
        print("Bad checksum! (0x{:02x})".format(checksum))

