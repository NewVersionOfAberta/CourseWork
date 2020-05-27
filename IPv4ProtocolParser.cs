using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace WindowsSniffer
{
    class IPv4ProtocolParser
    {
        private const byte VERSION_MASK = 0b11110000;
        private const byte IHL_MASK = 0b00001111;
        private const byte DSCP_MASK = 0b11111100;
        private const byte ECN_MASK = 0b00000011;
        private const ushort FLAGS_MASK = 0b11100000_00000000;
        private const ushort OFFSET_MASK = 0b00011111_1111111;

        private const int VERSION_OFFSET = 4;
        private const int DSCP_OFFSET = 2;
        private const int FLAGS_OFFSET = 13;

        private const int BYTES_PER_IP_WORD = 4;


        private byte fVersion;         // the four-bit version field. For IPv4, this is always equal to 4
        private int fIHL;             // IHL field contains the size of the IPv4 header, it has 4 bits that specify the number of 32-bit words in the header
        private byte fDSCP;            // DSCP for classifying and managing network traffic and providing quality of service (QoS); 
        private byte fECN;             // ECN is end-to-end notification of network congestion without dropping packets.
        private ushort fTotalLength;  // entire packet size in bytes, including header and data.
        private ushort fIdentification;// This field is an identification field and is primarily used for uniquely identifying the group of fragments of a single IP datagram.
                                       // but RFC 6864 now prohibits any such use.
        private byte fFlags;           // A three-bit field follows and is used to control or identify fragments.
        private ushort fOffset;        // Offset specifies the offset of a particular fragment relative to the beginning of the original unfragmented IP datagram.
        private byte fTTL;             // An eight-bit time to live field helps prevent datagrams from persisting
        private byte fProtocol;        // defines the protocol used in the data portion of the IP datagram.
        private ushort fChecksum;      // used for error-checking of the header
        private uint fSourseIP;        // IPv4 address of the sender of the packet
        private uint fDestIP;          // IPv4 address of the receiver of the packet
        private byte[] fOptions = null;       // if IHL > 5

        private byte[] fIPData;

        public IPv4ProtocolParser(byte[] packet, int received)
        {
            MemoryStream memoryStream = new MemoryStream(packet, 0, received);
            BinaryReader binaryReader = new BinaryReader(memoryStream);


            var tmpVersionAndIHL = binaryReader.ReadByte();

            fVersion = (byte)((tmpVersionAndIHL & VERSION_MASK) >> VERSION_OFFSET);
            fIHL = (tmpVersionAndIHL & IHL_MASK) * BYTES_PER_IP_WORD;

            var tmpDSCPandECN = binaryReader.ReadByte();

            fDSCP = (byte)((tmpDSCPandECN & DSCP_MASK) >> DSCP_OFFSET);
            fECN = (byte)(tmpDSCPandECN & ECN_MASK);

            fTotalLength = binaryReader.ReadUInt16();
            fIdentification = binaryReader.ReadUInt16();
            var tmpFlagsAndOffset = binaryReader.ReadUInt16();

            fFlags = (byte)((tmpFlagsAndOffset & FLAGS_MASK) >> FLAGS_OFFSET);
            fOffset = (ushort)(tmpFlagsAndOffset & OFFSET_MASK);

            fTTL = binaryReader.ReadByte();
            fProtocol = binaryReader.ReadByte();
            fChecksum = binaryReader.ReadUInt16();
            fSourseIP = binaryReader.ReadUInt32();
            fDestIP = binaryReader.ReadUInt32();

            if (fIHL > 5 * BYTES_PER_IP_WORD)
            {
                fOptions = new byte[(fIHL - 5 * BYTES_PER_IP_WORD)];
                for (int i = 0; i < fOptions.Length; i++)
                {
                    fOptions[i] = binaryReader.ReadByte();
                }
            }

            fIPData = new byte[fTotalLength - fIHL];

            Array.Copy(packet, fIHL, fIPData, 0, fIPData.Length);

        }

        private List<string> MakeSubProtocolList(byte protocol, byte[] data)
        {
            switch (protocol)
            {
                case 1:
                    ICMPParser iCMPParser = new ICMPParser(data);
                    return iCMPParser.GetList();
                case 6:
                    TCPParser tCPParser = new TCPParser(data);
                    return tCPParser.MakeList();
                case 17:
                    UDPParser uDPParser = new UDPParser(data);
                    return uDPParser.MakeList();
            }
            return null;
        }

        private string GetProtocol(byte protocol)
        {
            switch (protocol)
            {
                case 0:
                case 255: return "Reserved";
                case 1: return "ICMP";
                case 3: return "Gateway-to-Gateway";
                case 4: return "CMCC Gateway Monitoring Message";
                case 5: return "ST";
                case 6: return "TCP";
                case 7: return "UCL";
                case 9: return "Secure";
                case 10: return "BBN RCC Monitoring";
                case 11: return "NVP";
                case 12: return "PUP";
                case 13: return "Pluribus";
                case 14: return "Telenet";
                case 15: return "XNET";
                case 16: return "Chaos";
                case 17: return "UDP";
                case 18: return "Multiplexing";
                case 19: return "DCN";
                case 20: return "TAC Monitoring";
                case 63: return "any local network";
                case 64: return "SATNET and Backroom EXPAK";
                case 65: return "MIT Subnet Support";
                case 69: return "SATNET Monitoring";
                case 71: return "Internet Packet Core Utility";
                case 76: return "Backroom SATNET Monitoring";
                case 78: return "WIDEBAND Monitoring ";
                case 79: return "WIDEBAND EXPAK";
                default: return "Unassigned";
            }
        }

        public List<string> MakeList()
        {
            var packetCompList = new List<string>();
            var subProtocolList = MakeSubProtocolList(fProtocol, fIPData);
            packetCompList.Add(fVersion.ToString());
            packetCompList.Add(fIHL.ToString());
            packetCompList.Add(fDSCP.ToString());
            packetCompList.Add(fECN.ToString());
            packetCompList.Add(fTotalLength.ToString());
            packetCompList.Add(fIdentification.ToString());
            packetCompList.Add(fFlags.ToString());
            packetCompList.Add(fOffset.ToString());
            packetCompList.Add(fTTL.ToString());
            packetCompList.Add(GetProtocol(fProtocol));
            packetCompList.Add(fChecksum.ToString());
            packetCompList.Add(IPAddress.Parse(fSourseIP.ToString()).ToString());
            packetCompList.Add(IPAddress.Parse(fDestIP.ToString()).ToString());
            if (subProtocolList != null)
            {
                packetCompList.AddRange(subProtocolList);
            }
            return packetCompList;
        }
        

    }
}
