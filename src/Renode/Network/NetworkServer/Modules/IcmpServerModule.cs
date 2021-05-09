//
// Copyright (c) 2010-2021 Antmicro
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//

using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Threading.Tasks;

using PacketDotNet;

using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Exceptions;



namespace Antmicro.Renode.Network
{
    public class IcmpServerModule: IExternal
    {

        public IcmpServerModule(IPAddress serverIP, MACAddress serverMAC)
        {
            IP = serverIP;
            MAC = serverMAC;
        }
        
        private MACAddress MAC { get; set; }
        private IPAddress IP { get; set; }
        
        public void HandleIcmpPacket(Action<EthernetFrame> FrameReady, IPv4Packet packet, PhysicalAddress icmpDestinationAddress)
        {
            var icmpPacket = (ICMPv4Packet) packet.PayloadPacket;

            // If the destination address is not same as our IP, we ignore it
            if (packet.DestinationAddress.Equals(IP))
            {
                this.Log(LogLevel.Warning, "Wrong destination address: {0}",
                    packet.DestinationAddress);
                return;
            }

            // For now we only respond to Echo Requests so everything else is discarded
            if (!icmpPacket.TypeCode.Equals(ICMPv4TypeCodes.EchoRequest))
            {
                this.Log(LogLevel.Warning, "Unsupported ICMP code: {0}",
                    icmpPacket);
                return;
            }

            this.Log(LogLevel.Noisy, "Handling ICMP packet: {0}", icmpPacket);

            // We create an ICMP Response and Destination address to which
            // the response will be sent
            var icmpResponse = ICMPv4TypeCodes.EchoReply.AsRawBytes();
            var icmpDestination = icmpDestinationAddress;

            // We create the ethernet packet which will include the IPv4 packet
            var ethernetResponse = new EthernetPacket((PhysicalAddress) MAC,
                icmpDestination,
                EthernetPacketType.None); 

            // We create the IPv4 packet that will be sent in the Ethernet frame
            // ICMP as a protocol does not use a port, so we just give an IP address
            var ipPacket = new IPv4Packet(IP,
                ((IPv4Packet) packet.ParentPacket).SourceAddress);

            // We create the ICMP response packet that will be sent in the IPv4 packet
            var icmpPacketResponse =
                new ICMPv4Packet(new ByteArraySegment(icmpResponse));

            // We put the ICMP packet with the response into the IPv4 packet, then
            // we put that in the Ethernet frame, and recalculate the checksum
            ipPacket.PayloadPacket = icmpPacketResponse;
            ethernetResponse.PayloadPacket = ipPacket;
            icmpPacketResponse.UpdateCalculatedValues();

            this.Log(LogLevel.Noisy, "Sending response: {0}",
                ethernetResponse);

            // We finally create, and send the Ethernet frame
            EthernetFrame.TryCreateEthernetFrame(ethernetResponse.Bytes,
                false, out var response);
            FrameReady?.Invoke(response);
        }
    }
    
}