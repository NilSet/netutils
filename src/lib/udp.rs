use super::{n16, Checksum};
use std::{mem, slice, u8};

use ip::Ipv4Addr;

/// UDP header as defined in RFC 768
#[derive(Copy, Clone)]
#[repr(packed)]
pub struct UdpHeader {
    /// Source port
    pub src: n16,
    /// Destination port
    pub dst: n16,
    /// Length
    pub len: n16,
    /// Checksum
    pub checksum: Checksum,
}

/// UDP datagram for IPv4 stack consisting of header and data section
pub struct Udp {
    pub header: UdpHeader,
    pub data: Vec<u8>,
}

impl Udp {
    /// Read wire representation and parse it into its
    /// structural represantation.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= mem::size_of::<UdpHeader>() {
            unsafe {
                Option::Some(Udp {
                    header: *(bytes.as_ptr() as *const UdpHeader),
                    data: bytes[mem::size_of::<UdpHeader>()..bytes.len()].to_vec(),
                })
            }
        } else {
            Option::None
        }
    }

    /// Compile the `self` structure into its wire
    /// representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        unsafe {
            let header_ptr: *const UdpHeader = &self.header;
            let mut ret = Vec::from(slice::from_raw_parts(header_ptr as *const u8,
                                                          mem::size_of::<UdpHeader>()));
            ret.extend_from_slice(&self.data);
            ret
        }
    }

    /// Compute a checksum of the `self` datagram
    /// and compate it to the checksum received
    /// from the remote socket.
    pub fn is_valid(&self, src_addr: &Ipv4Addr, dst_addr: &Ipv4Addr) -> bool {
        // Checksum is the 16-bit one's complement of the one's complement sum of a
        // pseudo header of information from the IP header, the UDP header, and the
        // data,  padded  with zero octets  at the end (if  necessary)  to  make  a
        // multiple of two octets.
        //
        // The pseudo  header  conceptually prefixed to the UDP header contains the
        // source  address,  the destination  address,  the protocol,  and the  UDP
        // length.   This information gives protection against misrouted datagrams.
        // This checksum procedure is the same as is used in TCP.
        //
        //                   0      7 8     15 16    23 24    31
        //                  +--------+--------+--------+--------+
        //                  |          source address           |
        //                  +--------+--------+--------+--------+
        //                  |        destination address        |
        //                  +--------+--------+--------+--------+
        //                  |  zero  |protocol|   UDP length    |
        //                  +--------+--------+--------+--------+
        //
        // If the computed  checksum  is zero,  it is transmitted  as all ones (the
        // equivalent  in one's complement  arithmetic).   An all zero  transmitted
        // checksum  value means that the transmitter  generated  no checksum  (for
        // debugging or for higher level protocols that don't care).
        if self.header.checksum.data == 0 {
            true
        } else {
            let mut header = self.header;
            header.checksum.data = 0;
            let mut computed_checksum: u16 = Checksum::compile(unsafe {
                // Pseudo header
                Checksum::sum(src_addr.bytes.as_ptr() as usize, src_addr.bytes.len()) +
                Checksum::sum(dst_addr.bytes.as_ptr() as usize, dst_addr.bytes.len()) +
                Checksum::sum((&0u8 as *const u8) as usize, mem::size_of::<u8>()) +
                Checksum::sum((&0x11u8 as *const u8) as usize, mem::size_of::<u8>()) +
                Checksum::sum((&header.len as *const n16) as usize, mem::size_of::<n16>()) +
                // Real header
                Checksum::sum((&header as *const UdpHeader) as usize, mem::size_of::<UdpHeader>()) +
                // Data
                Checksum::sum(self.data.as_ptr() as usize, self.data.len())
            });
            println!("computed checksum: {:x}", computed_checksum);
            if computed_checksum == 0 {
                computed_checksum = 0xFFFF;
            }
            if computed_checksum == self.header.checksum.data {
                true
            } else {
                false
            }
        }
    }
}

#[test]
fn upd_header_computation() {
    let addr = Ipv4Addr::from_str("127.0.0.1");
    let source_port = n16::new(54110);
    let dest_port = n16::new(25000);

    let datagram1 = Udp {
        header: UdpHeader {
            src: source_port,
            dst: dest_port,
            len: n16::new(10),
            checksum: Checksum {
                data: 0x9bc6
            }
        },
        data: "1\n".as_bytes().to_vec()
    };

    let datagram2 = Udp {
        header: UdpHeader {
            src: source_port,
            dst: dest_port,
            len: n16::new(10),
            checksum: Checksum {
                data: 0x6ac6
            }
        },
        data: "b\n".as_bytes().to_vec()
    };

    let datagram3 = Udp {
        header: UdpHeader {
            src: source_port,
            dst: dest_port,
            len: n16::new(13),
            checksum: Checksum {
                data: 0xff06
            }
        },
        data: "aabb\n".as_bytes().to_vec()
    };

    let res1 = datagram1.is_valid(&addr, &addr);
    let res2 = datagram2.is_valid(&addr, &addr);
    let res3 = datagram3.is_valid(&addr, &addr);

    assert!(res1);
    assert!(res2);
    assert!(res3);

    println!("Trying to compute UDP header");
}
