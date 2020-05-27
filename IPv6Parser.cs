using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace WindowsSniffer
{
    class IPv6Parser
    {
        private const uint VERSION_MASK = 0b11110000_00000000_00000000_00000000;
        private const uint TRAFFIC_MASK = 0b00001111_11110000_00000000_00000000;
        private const uint LABEL_MASK =   0b00000000_00001111_11111111_11111111;

        private const int VERSION_OFFSET = 28;
        private const int TRAFFIC_OFFSET = 20;

        private const int HEADER_LEN = 40;

        private byte fVersion;
        private byte fTrafficClass;
        private int fFlowLabel;
        private ushort fPayloadLen;
        private byte fNextHeader;
        private byte fHopLimit;
        private IPAddress fSourseIP;
        private IPAddress fDestIP;

        private byte[] fData;

        List<string> list = new List<string>();

        public IPv6Parser(byte[] packet, int received)
        {
            MemoryStream memoryStream = new MemoryStream(packet, 0, received);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            int tmpVersTraffAndLabel = binaryReader.ReadInt32();

            fVersion = (byte)((tmpVersTraffAndLabel & VERSION_MASK) >> VERSION_OFFSET);
            fTrafficClass = (byte)((tmpVersTraffAndLabel & TRAFFIC_MASK) >> TRAFFIC_OFFSET);
            fFlowLabel = (int)(tmpVersTraffAndLabel & LABEL_MASK);
            fPayloadLen = binaryReader.ReadUInt16();
            fNextHeader = binaryReader.ReadByte();
            fHopLimit = binaryReader.ReadByte();
            fSourseIP = IPAddress.Parse(Encoding.UTF8.GetString(binaryReader.ReadBytes(16)));
            fDestIP = IPAddress.Parse(Encoding.UTF8.GetString(binaryReader.ReadBytes(16)));
            MakeBaseIPv6List();
            fData = new byte[fPayloadLen];
            Array.Copy(packet, HEADER_LEN, fData, 0, fPayloadLen);

        }

        private string GetNextByCode(byte iCode)
        {
            switch (iCode)
            {
                case 0:
                    return "Hop-by-Hop Options";
                case 60:
                    return "Destination Options";
                case 43:
                    return "Routing";
                case 44:
                    return "Fragment";
                case 51:
                    return "Authentication Header";
                case 50:
                    return "Encapsulating Security Payload";
                default: 
                    return "Unknown";
            }
        }
        //private void MakeExtHeaderList(byte tNextHeader, byte[] packetPart)
        //{
        //    byte nextHeader = packetPart[0];
        //    byte headerLen = packetPart[1];
        //    list.Add(nextHeader.ToString());
        //    list.Add(headerLen.ToString());
        //    byte[] data;
        //    switch (tNextHeader)
        //    {
        //        case 0: //Hop-by-Hop option header
        //        case 60: //Destination Options header 
        //        case 43: //Routing Header
        //            list.Add(packetPart[2].ToString());
        //            list.Add(packetPart[3].ToString());
        //            data = new byte[headerLen];
        //            Array.Copy(packetPart, 8, data, 0, headerLen);
        //            break;
                
        //            list.Add(packetPart[2].ToString());
        //            list.Add(packetPart[3].ToString());
        //            data = new byte[headerLen];
        //            Array.Copy(packetPart, 8, data, 0, headerLen);



        //    }
        //}

        public List<string> MakeBaseIPv6List()
        {
            list.Add(fVersion.ToString());
            list.Add(fTrafficClass.ToString());
            list.Add(fFlowLabel.ToString());
            list.Add(fPayloadLen.ToString());
            list.Add(fNextHeader.ToString());
            list.Add(fHopLimit.ToString());
            list.Add(fSourseIP.ToString());
            list.Add(fDestIP.ToString());
            list.Add(Encoding.UTF8.GetString(fData));
            return list;
        }

    }
}
