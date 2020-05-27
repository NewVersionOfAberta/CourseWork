using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WindowsSniffer
{


    class TCPParser
    {
        private ushort fSoursePort;
        private ushort fDestPort;
        private uint fSequensNumber;
        private uint fAcknowlegmentNum;
        private int fDataOffset;
        private int fFlags;
        private ushort fWindowSize;
        private ushort fCheckSum;
        private ushort fUrgentPointer;
        private byte[] fOptions = null;
        private byte[] fData;


        private const ushort OFFSET_MASK = 0b11110000_00000000;
        private const ushort FLAGS_MASK = 0b00000000_0011111;
        private const int OFFSET = 12;

        private const int BYTES_PER_IP_WORD = 4;

        public TCPParser(byte[] packet)
        {
            MemoryStream memoryStream = new MemoryStream(packet, 0, packet.Length);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            fSoursePort = binaryReader.ReadUInt16();
            fDestPort = binaryReader.ReadUInt16();
            fSequensNumber = binaryReader.ReadUInt32();
            fAcknowlegmentNum = binaryReader.ReadUInt32();
            var tmpOffsetAndFlsgs = binaryReader.ReadUInt16();
            fDataOffset = ((tmpOffsetAndFlsgs & OFFSET_MASK) >> OFFSET) * BYTES_PER_IP_WORD;
            fFlags = tmpOffsetAndFlsgs & FLAGS_MASK;
            fWindowSize = binaryReader.ReadUInt16();
            fCheckSum = binaryReader.ReadUInt16();
            fUrgentPointer = binaryReader.ReadUInt16();
            if (fDataOffset - 5 * BYTES_PER_IP_WORD > 0)
            {
                fOptions = binaryReader.ReadBytes(fDataOffset - 5 * BYTES_PER_IP_WORD);
            }

            fData = new byte[packet.Length - fDataOffset];
            Array.Copy(packet, fDataOffset, fData, 0, fData.Length);
        }

        public List<string> MakeList()
        {
            List<string> list = new List<string>();
            list.Add(fSoursePort.ToString());
            list.Add(fDestPort.ToString());
            list.Add(fSequensNumber.ToString());
            list.Add(fAcknowlegmentNum.ToString());
            list.Add(fDataOffset.ToString());
            list.Add(fFlags.ToString());
            list.Add(fWindowSize.ToString());
            list.Add(fCheckSum.ToString());
            list.Add(fUrgentPointer.ToString());
            if (fOptions != null)
            {
                list.Add(Encoding.UTF8.GetString(fOptions));
            }
            else
            {
                list.Add("No");
            }
            list.Add(Encoding.UTF8.GetString(fData));
            return list;
        }
    }
}
