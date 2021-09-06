#Resource: http://allanrbo.blogspot.com/2011/12/raw-sockets-with-bpf-in-python.html
from ctypes import create_string_buffer, addressof
from struct import pack, unpack
import socket

# A subset of Berkeley Packet Filter constants and macros, as defined in
# linux/filter.h.




# instruction code, jump true, jump false, value to check
def _bpf_jump(code, k, jt, jf):
    return pack('HBBI', code, jt, jf, k)


def _bpf_stmt(code, k):
    return _bpf_jump(code, k, 0, 0)


def ip2int(addr):
    return unpack("!I", socket.inet_aton(addr))[0]


# filters for the ether payload
def create_filter_ip(src_addr, dst_addr, src_port, dst_port, identifier):

    if not isinstance(src_addr, str):
        raise Exception('Source address is not a string')
    if not isinstance(dst_addr, str):
        raise Exception('Destination address is not a string')
    if not isinstance(src_port, int):
        raise Exception('Source port is not an int')
    if not isinstance(dst_port, int):
        raise Exception('Destination port is not an int')
    if not isinstance(identifier, bytes):
        raise Exception('Identifier is not of type bytes')

    if len(identifier) != 4:
        raise Exception('Identifier is not 4 Bytes long\n currently only a identifier of 4 Bytes is supported')

    # convert IP addresses to int for later use
    try:
        src_addr_int = ip2int(src_addr)
        dst_addr_int = ip2int(dst_addr)
    except OSError as oserr:
        raise oserr

    # convert identifier bytes to int
    identifier_int = unpack("!I", identifier)[0]

    #build filter list
    # Instruction classes
    BPF_LD = 0x00
    BPF_JMP = 0x05
    BPF_RET = 0x06

    # ld/ldx fields
    BPF_H = 0x08
    BPF_B = 0x10
    BPF_ABS = 0x20

    # alu/jmp fields
    BPF_JEQ = 0x10
    BPF_K = 0x00

    # Ordering of the filters is backwards of what would be intuitive for
    # performance reasons: the check that is most likely to fail is first.
    filters_list =[
        ## load word from address 48 (where the identifier is located at the start tof the RTP payload)
        _bpf_stmt(BPF_LD | BPF_ABS, 48),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, identifier_int, 0, 11),

        ## load word from address 28 where should start with 0x90
        _bpf_stmt(BPF_LD | BPF_B | BPF_ABS, 28),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0x90, 0, 9),

        # check udp dst port
        _bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 22),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, dst_port, 0, 7),

        # check udp src port
        _bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 20),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, src_port, 0, 5),

        # check dst ip
        _bpf_stmt(BPF_LD | BPF_ABS, 16),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, dst_addr_int , 0, 3),

        # check dst ip
        _bpf_stmt(BPF_LD | BPF_ABS, 12),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, src_addr_int , 0, 1),

        #tcpdump uses 0x00040000, so better than 0x0fffffff? dont understand the return address
        _bpf_stmt(BPF_RET | BPF_K, 0x00040000),  # pass
        _bpf_stmt(BPF_RET | BPF_K, 0)  # reject
    ]



    # Ordering of the filters is backwards of what would be intuitive for
    # performance reasons: the check that is most likely to fail is first.
    """
    filters_list = [
        # Must have dst port 67. Load (BPF_LD) a half word value (BPF_H) in
        # ethernet frame at absolute byte offset 36 (BPF_ABS). If value is equal to
        # 67 then do not jump, else jump 5 statements.
        _bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 36),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 67, 0, 5),

        # Must be UDP (check protocol field at byte offset 23)
        _bpf_stmt(BPF_LD | BPF_B | BPF_ABS, 23),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0x11, 0, 3),

        # Must be IPv4 (check ethertype field at byte offset 12)
        _bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 12),
        _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 1),

        _bpf_stmt(BPF_RET | BPF_K, 0x0fffffff),  # pass
        _bpf_stmt(BPF_RET | BPF_K, 0),  # reject
    ]
    """

    # Create filters struct and fprog struct to be used by SO_ATTACH_FILTER, as
    # defined in linux/filter.h.
    filters = b""
    for f in filters_list:
        filters += f

    # doesnt work to return a address of a struct therefore the callee has to implement the following:
    """
    filters, filters_list_len = filter.create_filter_ip('127.0.0.1', '127.0.0.1', 42069, 8888, b"\xca\xfe\xba\xbe")

    b = create_string_buffer(filters)
    mem_addr_of_filters = addressof(b)
    print(mem_addr_of_filters)
    fprog = pack('HL', filters_list_len, mem_addr_of_filters)

    SO_ATTACH_FILTER = 26

    s.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, fprog)
    """

    return filters, len(filters_list)

"""
# As defined in asm/socket.h
SO_ATTACH_FILTER = 26
"""