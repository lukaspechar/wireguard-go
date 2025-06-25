package device

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ParseAndLogPacket inspects a raw packet and logs its type and addresses.
// Returns true if the packet is a valid IPv4 or IPv6 packet, false otherwise
func ParseAndLogPacket(log *Logger, packet []byte, outgoing bool) bool {

	logPefix := "<<"
	if outgoing {
		logPefix = ">>"
	}

	if len(packet) == 0 {
		if log != nil {
			log.Verbosef("%s!! Skipping empty/keepalive packet", logPefix)
		}
		return false
	}

	ipVersion := packet[0] >> 4
	switch ipVersion {
	case 4:
		if len(packet) < ipv4.HeaderLen {
			if log != nil {
				log.Verbosef("%s!! Invalid IPv4 packet: too short (%d bytes)", logPefix, len(packet))
			}
			return false
		}
		src := net.IP(packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len])
		dst := net.IP(packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len])
		if log != nil {
			log.Verbosef("%s IPv4 packet: %s ➔ %s (%d bytes)", logPefix, src, dst, len(packet))
		}
		return true

	case 6:
		if len(packet) < ipv6.HeaderLen {
			if log != nil {
				log.Verbosef("%s!! Invalid IPv6 packet: too short (%d bytes)", logPefix, len(packet))
			}
			return false
		}
		src := net.IP(packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len])
		dst := net.IP(packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len])
		if log != nil {
			log.Verbosef("%s IPv6 packet: %s ➔ %s (%d bytes)", logPefix, src, dst, len(packet))
		}
		return true

	default:
		if log != nil {
			log.Verbosef("%s !!Non-IP packet (version %d)", logPefix, ipVersion)
		}
		return false
	}
}
