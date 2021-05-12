//
// Copyright (c) 2010-2021 Antmicro
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure;
using Antmicro.Renode.Exceptions;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Utilities;
using PacketDotNet;
using PacketDotNet.Utils;


namespace Antmicro.Renode.Network
{
    public class IcmpServerModule : IExternal
    {
        public IcmpServerModule(IPAddress serverIP, MACAddress serverMAC)
        {
            IP = serverIP;
            MAC = serverMAC;
        }



        private MACAddress MAC { get; set; }
        private IPAddress IP { get; set; }


        /// <summary>
        /// Handles the IPv4 packet with an ICMPv4 request by replying to it if the request is supported
        /// </summary>
        /// <param name="FrameReady"></param>
        /// <param name="ipv4Packet"></param>
        /// <param name="icmpDestinationAddress"></param>
        public void HandleIcmpPacket(Action<EthernetFrame> FrameReady, IPv4Packet ipv4Packet,
            PhysicalAddress icmpDestinationAddress)
        {

            if (!CreateIcmpResponse(ipv4Packet, out var icmpv4PacketResponse))
            {
                return;
            }

            this.Log(LogLevel.Noisy, "Handling ICMP packet: {0}", (ICMPv4Packet)ipv4Packet.PayloadPacket);

            var ipv4ResponePacket = CreateIPv4Packet(ipv4Packet);
            var response = CreateEthernetFramePacket(ipv4ResponePacket, icmpv4PacketResponse, icmpDestinationAddress);

            FrameReady?.Invoke(response);
        }


        /// <summary>
        /// Checks if a given ICMPv4 request is supported, and if so, creates a reply
        /// </summary>
        /// <param name="ipv4Packet"></param>
        /// <param name="icmpPacketResponse"></param>
        /// <returns></returns>
        private bool CreateIcmpResponse(IPv4Packet ipv4Packet, out ICMPv4Packet icmpPacketResponse)
        {
            icmpPacketResponse = null;

            if (!GetReplyIfRequestSupported(ipv4Packet, out var byteReply))
            {
                return false;
            }

            icmpPacketResponse = CreateIcmpv4Packet(ipv4Packet, byteReply);
            return true;
        }


        /// <summary>
        /// Checks if the destination address matches our IP,
        /// and creates a reply if we support a given request
        /// </summary>
        /// <param name="ipv4Packet"></param>
        /// <param name="byteReply"></param>
        /// <returns></returns>
        bool GetReplyIfRequestSupported(IPv4Packet ipv4Packet, out byte[] byteReply)
        {
            byteReply = null;

            // If the destination address is not same as our IP, we ignore it
            if (ipv4Packet.DestinationAddress.Equals(IP))
            {
                this.Log(LogLevel.Warning, "Wrong destination address: {0}",
                    ipv4Packet.DestinationAddress);
                return false;
            }

            // For now we only respond to Echo Requests so everything else is discarded
            if (!((ICMPv4Packet)ipv4Packet.PayloadPacket).TypeCode.Equals(ICMPv4TypeCodes.EchoRequest))
            {
                this.Log(LogLevel.Warning, "Unsupported ICMP code: {0}",
                    ((ICMPv4Packet)ipv4Packet.PayloadPacket));
                return false;
            }

            ICMPv4TypeCodes.EchoReply.AsRawBytes().CopyTo(byteReply, 0);
            return true;
        }


        /// <summary>
        /// Creates an ICMPv4 packed with a given response
        /// </summary>
        /// <param name="ipv4Packet"></param>
        /// <param name="byteReply"></param>
        /// <returns></returns>
        private ICMPv4Packet CreateIcmpv4Packet(IPv4Packet ipv4Packet, byte[] byteReply)
        {
            var icmpv4Packet = (ICMPv4Packet)ipv4Packet.PayloadPacket;

            var icmpv4PacketResponse = new ICMPv4Packet(new ByteArraySegment(byteReply));

            // We can copy that from request packet because they are the same in the request and the replay
            icmpv4Packet.Data.CopyTo(icmpv4PacketResponse.Data, 0);
            icmpv4PacketResponse.ID = icmpv4Packet.ID;
            icmpv4PacketResponse.Sequence = icmpv4Packet.Sequence;

            return icmpv4PacketResponse;
        }


        /// <summary>
        /// Creates an IPv4 response packet
        /// </summary>
        /// <param name="ipv4Packet"></param>
        /// <returns></returns>
        private IPv4Packet CreateIPv4Packet(IPv4Packet ipv4Packet)
        {
            var ipv4PacketResponse = new IPv4Packet(IP,
                ((IPv4Packet)ipv4Packet.ParentPacket).SourceAddress);
            return ipv4PacketResponse;
        }


        /// <summary>
        /// Creates an Ethernet Frame from a given IPv4, and ICMPv4 packet
        /// </summary>
        /// <param name="ipv4Packet"></param>
        /// <param name="icmpv4PacketResponse"></param>
        /// <param name="icmpDestinationAddress"></param>
        /// <returns></returns>
        private EthernetFrame CreateEthernetFramePacket(IPv4Packet ipv4Packet, ICMPv4Packet icmpv4PacketResponse,
            PhysicalAddress icmpDestinationAddress)
        {
            ipv4Packet.PayloadPacket = icmpv4PacketResponse;

            var ethernetResponse = new EthernetPacket((PhysicalAddress)MAC,
                icmpDestinationAddress,
                EthernetPacketType.None)
            {
                PayloadPacket = ipv4Packet
            };
            icmpv4PacketResponse.UpdateCalculatedValues();

            this.Log(LogLevel.Noisy, "Sending response: {0}",
                ethernetResponse);

            EthernetFrame.TryCreateEthernetFrame(ethernetResponse.Bytes,
                false, out var response);
            return response;
        }
    }
}
