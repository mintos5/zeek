// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/gre/GRE.h"

#include <pcap.h> // For DLT_ constants

#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::GRE;

static unsigned int gre_header_len(uint16_t flags = 0)
	{
	unsigned int len = 4; // Always has 2 byte flags and 2 byte protocol type.

	if ( flags & 0x8000 )
		// Checksum/Reserved1 present.
		len += 4;

	// Not considering routing presence bit since it's deprecated ...

	if ( flags & 0x2000 )
		// Key present.
		len += 4;

	if ( flags & 0x1000 )
		// Sequence present.
		len += 4;

	if ( flags & 0x0080 )
		// Acknowledgement present.
		len += 4;

	return len;
	}

GREAnalyzer::GREAnalyzer() : zeek::packet_analysis::Analyzer("GRE") { }

bool GREAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! packet->ip_hdr )
		{
		reporter->InternalError("GREAnalyzer: ip_hdr not provided from earlier analyzer");
		return false;
		}

	if ( ! BifConst::Tunnel::enable_gre )
		{
		Weird("GRE_tunnel", packet);
		return false;
		}

	if ( len < gre_header_len() )
		{
		Weird("truncated_GRE", packet);
		return false;
		}

	int proto = packet->proto;
	int gre_link_type = DLT_RAW;

	uint16_t flags_ver = ntohs(*((uint16_t*)(data + 0)));
	uint16_t proto_typ = ntohs(*((uint16_t*)(data + 2)));
	int gre_version = flags_ver & 0x0007;

	unsigned int eth_len = 0;
	unsigned int gre_len = gre_header_len(flags_ver);
	unsigned int ppp_len = gre_version == 1 ? 4 : 0;
	unsigned int erspan_len = 0;

	if ( gre_version != 0 && gre_version != 1 )
		{
		Weird("unknown_gre_version", packet, util::fmt("version=%d", gre_version));
		return false;
		}

	if ( gre_version == 0 )
		{
		if ( proto_typ == 0x6558 )
			{
			// transparent ethernet bridging
			if ( len > gre_len + 14 )
				{
				eth_len = 14;
				gre_link_type = DLT_EN10MB;
				}
			else
				{
				Weird("truncated_GRE", packet);
				return false;
				}
			}

		else if ( proto_typ == 0x88be )
			{
			if ( len > gre_len + 14 )
				{
				// ERSPAN type I
				erspan_len = 0;
				eth_len = 14;
				gre_link_type = DLT_EN10MB;
				bool have_sequence_header = ((flags_ver & 0x1000) == 0x1000);
				if ( have_sequence_header )
					{
					// ERSPAN type II
					erspan_len += 8;
					if ( len < gre_len + eth_len + erspan_len )
						{
						Weird("truncated_GRE", packet);
						return false;
						}
					}
				}
			else
				{
				Weird("truncated_GRE", packet);
				return false;
				}
			}

		else if ( proto_typ == 0x22eb )
			{
			// ERSPAN type III
			if ( len > gre_len + 14 + 12 )
				{
				erspan_len = 12;
				eth_len = 14;
				gre_link_type = DLT_EN10MB;

				auto flags = data + gre_len + erspan_len - 1;
				bool have_opt_header = ((*flags & 0x01) == 0x01);

				if ( have_opt_header )
					{
					if ( len > gre_len + erspan_len + 8 + eth_len )
						erspan_len += 8;
					else
						{
						Weird("truncated_GRE", packet);
						return false;
						}
					}
				}
			else
				{
				Weird("truncated_GRE", packet);
				return false;
				}
			}

		else if ( proto_typ == 0x8200 )
			{
			// ARUBA. The next thing that follows an ARUBA header is an 802.11 QoS header, and then
			// things get dumb based on what's in that header. Normally, it'd just be an LLC header
			// that we can skip, but not always. There's other things that can happen based on
			// the flags present in the header.

			if ( len > gre_len + 26 )
				{
				const uint8_t* ieee80211 = data + gre_len + 26;
				// CCMP is an encrypted payload inside of the QoS, and we can't decrypt it. Just
				// report a weird and move on. The presence of CCMP is denoted by the "Protected"
				// flag in the Control Field flags, which are byte #2 in the header.
				if ( (ieee80211[1] >> 6) == 1 )
					{
					Weird("aruba_ccmp_encryption", packet);
					return false;
					}

				// Aggregates. It's possible for an 802.11 packet to contain multiple inner
				// packets. This is frame aggregation, which in an optimization to allow 802.11
				// to batch multiple smaller packets into one. We don't properly handle this
				// since it would require some amount of reentrancy in the encapsulation
				// code. In the meantime, parse out the first one and skip the rest. The
				// presence of aggregates is denoted by the QoS Control -> Payload Type flag
				// being set to 1.
				else if ( (ieee80211[24] >> 7) == 1 )
					{
					Weird("aruba_aggregate_msdu", packet);
					return false;
					}

				// Otherwise, we just get a 802.11 QoS header followed by a happy LLC header
				// and everything is great and we can parse the inner payload for once. Well,
				// assuming we actually have enough data for that.
				else if ( len > gre_len + 26 + 8 )
					{
					gre_link_type = DLT_EN10MB;
					erspan_len = 34;

					// TODO: fix this, but it's gonna require quite a bit more surgery to the GRE
					// analyzer to make it more independent from the IPTunnel analyzer.
					// Setting gre_version to 1 here tricks the IPTunnel analyzer into treating the
					// first header as IP instead of Ethernet which it does by default when
					// gre_version is 0.
					gre_version = 1;
					proto = (data[gre_len + 34] & 0xF0) >> 4;
					}
				else
					{
					Weird("truncated_GRE", packet);
					return false;
					}
				}
			else
				{
				Weird("truncated_GRE", packet);
				return false;
				}
			}
		}

	else // gre_version == 1
		{
		if ( proto_typ != 0x880b )
			{
			// Enhanced GRE payload must be PPP.
			Weird("egre_protocol_type", packet, util::fmt("proto=%d", proto_typ));
			return false;
			}
		}

	if ( flags_ver & 0x4000 )
		{
		// RFC 2784 deprecates the variable length routing field
		// specified by RFC 1701. It could be parsed here, but easiest
		// to just skip for now.
		Weird("gre_routing", packet);
		return false;
		}

	if ( flags_ver & 0x0078 )
		{
		// Expect last 4 bits of flags are reserved, undefined.
		Weird("unknown_gre_flags", packet);
		return false;
		}

	if ( len < gre_len + ppp_len + eth_len + erspan_len )
		{
		Weird("truncated_GRE", packet);
		return false;
		}

	if ( gre_version == 1 && proto_typ != 0x8200 )
		{
		uint16_t ppp_proto = ntohs(*((uint16_t*)(data + gre_len + 2)));

		if ( ppp_proto != 0x0021 && ppp_proto != 0x0057 )
			{
			Weird("non_ip_packet_in_encap", packet);
			return false;
			}

		proto = (ppp_proto == 0x0021) ? IPPROTO_IPV4 : IPPROTO_IPV6;
		}

	data += gre_len + ppp_len + erspan_len;
	len -= gre_len + ppp_len + erspan_len;

	// Treat GRE tunnel like IP tunnels, fallthrough to logic below now
	// that GRE header is stripped and only payload packet remains.
	// The only thing different is the tunnel type enum value to use.
	packet->tunnel_type = BifEnum::Tunnel::GRE;
	packet->gre_version = gre_version;
	packet->gre_link_type = gre_link_type;
	packet->proto = proto;

	ForwardPacket(len, data, packet);

	return true;
	}
