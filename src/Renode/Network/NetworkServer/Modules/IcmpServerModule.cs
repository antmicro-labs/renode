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
        public IcmpServerModule(NetworkServer MyParentServer, IPAddress serverIP, MACAddress serverMAC)
        {
            IP = serverIP;
            MAC = serverMAC;
            ParentServer = MyParentServer;
        }



        private MACAddress MAC { get; set; }
        private IPAddress IP { get; set; }
        private NetworkServer ParentServer { get; set; }

        /// <summary>
        /// Handles the IPv4 packet with an ICMPv4 request by replying to it if the request is supported
        /// </summary>
        /// <param name="FrameReady"></param>
        /// <param name="ipv4Packet"></param>
        /// <param name="icmpDestinationAddress"></param>
        public void HandleIcmpPacket(Action<EthernetFrame> FrameReady, IPv4Packet ipv4Packet,
            PhysicalAddress icmpDestinationAddress)
        {
            ParentServer.Log(LogLevel.Noisy, "Handling ICMP packet: {0}", (ICMPv4Packet)ipv4Packet.PayloadPacket);
            if (!CreateIcmpResponse(ipv4Packet, out var icmpv4PacketResponse))
            {
                ParentServer.Log(LogLevel.Warning, "Failed to create an ICMPv4 response for this packet: {0}", (ICMPv4Packet)ipv4Packet.PayloadPacket);
                return;
            }

            var ipv4ResponsePacket = CreateIPv4Packet(ipv4Packet);

            if (!CreateEthernetFramePacket(ipv4ResponsePacket, icmpv4PacketResponse, icmpDestinationAddress, out var response))
            {
                ParentServer.Log(LogLevel.Warning, "Failed to create an EthernetFramePacket response for this packet: {0}", (ICMPv4Packet)ipv4Packet.PayloadPacket);
                return;
            }

            ParentServer.Log(LogLevel.Noisy, "Sending EthernetFrame with a response: {0}", response.ToString());
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

            ParentServer.Log(LogLevel.Warning, "Handling ICMP packet: {0}", (ICMPv4Packet)ipv4Packet.PayloadPacket);
            this.Log(LogLevel.Warning, "Handling ICMP packet: {0}", (ICMPv4Packet)ipv4Packet.PayloadPacket);
            if (!GetReplyIfRequestSupported(ipv4Packet, out var byteReply))
            {
                ParentServer.Log(LogLevel.Warning, "Cannot reply to a packet. Either the request is not supported or the response packet creation failed: {0}", (ICMPv4Packet)ipv4Packet.PayloadPacket);
                return false;
            }

            icmpPacketResponse = CreateIcmpv4Packet(ipv4Packet, byteReply);
            ParentServer.Log(LogLevel.Noisy, "Created an ICMPv4 response: {0}", icmpPacketResponse.PayloadPacket);
            return true;
        }


        /// <summary>
        /// Checks if the destination address matches our IP,
        /// and creates a reply if we support a given request
        /// </summary>
        /// <param name="ipv4Packet"></param>
        /// <param name="byteReply"></param>
        /// <returns></returns>
        private bool GetReplyIfRequestSupported(IPv4Packet ipv4Packet, out byte[] byteReply)
        {
            // byteReply =  null;
            byteReply = new byte[8];
            for (var i=0; i<byteReply.Length; i++)
            {
                byteReply[i] = 0;
            }

            var ipv4PacketPayload = (ICMPv4Packet)ipv4Packet.PayloadPacket;
            ParentServer.Log(LogLevel.Noisy, "Getting a reply if we support it");

            if (!ipv4Packet.DestinationAddress.Equals(IP))
            {
                ParentServer.Log(LogLevel.Warning, "The destination IP is not equal to our IP, so we ignore the request: {0}", ipv4PacketPayload);
                return false;
            }
            ParentServer.Log(LogLevel.Noisy, "The IP address is equal to our IP, so we try to service the request: {0}", ipv4PacketPayload);

            if (!ipv4PacketPayload.TypeCode.Equals(ICMPv4TypeCodes.EchoRequest))
            {
                ParentServer.Log(LogLevel.Warning, "Unsupported ICMP code: {0}",
                    ipv4PacketPayload);
                return false;
            }
            ParentServer.Log(LogLevel.Noisy, "The ICMP code is supported so we service it: {0}", ipv4PacketPayload);

            (BitConverter.GetBytes((ushort)ICMPv4TypeCodes.EchoReply)).CopyTo(byteReply, 0);
            ParentServer.Log(LogLevel.Noisy, "Created a byte reply to the ICMP request: {0}", String.Join(",", byteReply.ToString()));
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
            ParentServer.Log(LogLevel.Noisy, "Creating an ICMPv4 response packet");
            var icmpv4Packet = (ICMPv4Packet)ipv4Packet.PayloadPacket;
            var icmpv4PacketResponse = new ICMPv4Packet(new ByteArraySegment(byteReply));

            // We can copy that from request packet because they are the same in the request and the reply
            icmpv4Packet.Data.CopyTo(icmpv4PacketResponse.Data, 0);
            icmpv4PacketResponse.ID = icmpv4Packet.ID;
            icmpv4PacketResponse.Sequence = icmpv4Packet.Sequence;

            ParentServer.Log(LogLevel.Noisy, "Created ICMPv4 response packet: {0}", icmpv4PacketResponse.PayloadPacket);
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

            ParentServer.Log(LogLevel.Noisy, "Created IPv4 packet response");
            return ipv4PacketResponse;
        }


        /// <summary>
        /// Creates an Ethernet Frame from a given IPv4, and ICMPv4 packet
        /// </summary>
        /// <param name="ipv4Packet"></param>
        /// <param name="icmpv4PacketResponse"></param>
        /// <param name="icmpDestinationAddress"></param>
        /// <returns></returns>
        private bool CreateEthernetFramePacket(IPv4Packet ipv4Packet, ICMPv4Packet icmpv4PacketResponse,
            PhysicalAddress icmpDestinationAddress, out EthernetFrame response)
        {
            ParentServer.Log(LogLevel.Noisy, "Creating EthernetFramePacket response");
            response = null;
            ipv4Packet.PayloadPacket = icmpv4PacketResponse;

            var ethernetResponse = new EthernetPacket((PhysicalAddress)MAC,
                icmpDestinationAddress,
                EthernetPacketType.None)
            {
                PayloadPacket = ipv4Packet
            };
            icmpv4PacketResponse.UpdateCalculatedValues();
            ParentServer.Log(LogLevel.Noisy, "Created EthernetPacket: {0}", ethernetResponse.ToString());


            if (!EthernetFrame.TryCreateEthernetFrame(ethernetResponse.Bytes,
                true, out var responseEthernetFrame))
            {
                ParentServer.Log(LogLevel.Warning, "Failed to create EthernetFrame response");
                return false;
            }
            response = responseEthernetFrame;
            ParentServer.Log(LogLevel.Noisy, "Created EthernetFramePacket response: {0}", response.ToString());

            return true;
        }
    }
}
