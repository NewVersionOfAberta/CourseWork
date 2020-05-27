using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WindowsSniffer
{ 


    class UDPParser
    {
        private ushort fSoursePort;
        private ushort fDestPort;
        private ushort fDatagramLen;
        private ushort fChecksum;
        private byte[] fData;

        private const int DATAGRAMM_HEADER_LEN = 8;

        public UDPParser(byte[] packet)
        {
            MemoryStream memoryStream = new MemoryStream(packet, 0, packet.Length);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            fSoursePort = binaryReader.ReadUInt16();
            fDestPort = binaryReader.ReadUInt16();
            fDatagramLen = binaryReader.ReadUInt16();
            fChecksum = binaryReader.ReadUInt16();

            fData = new byte[packet.Length - DATAGRAMM_HEADER_LEN];
            Array.Copy(packet, DATAGRAMM_HEADER_LEN, fData, 0, packet.Length - DATAGRAMM_HEADER_LEN);
        }

        public List<string> MakeList()
        {
            List<string> list = new List<string>();
            list.Add(fSoursePort.ToString());
            list.Add(fDestPort.ToString());
            list.Add(fDatagramLen.ToString());
            list.Add(fChecksum.ToString());
            list.Add(Encoding.UTF8.GetString(fData));
            return list;
        }
    }
}
