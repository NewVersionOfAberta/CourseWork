using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WindowsSniffer
{
    class ICMPParser
    {
        private byte fType;
        private byte fCode;
        private ushort fCheckSum;
        private uint fUnused;
        private byte[] fData;

        

        private const int FIX_LEN = 32;

        public ICMPParser(byte[] packet)
        {
            MemoryStream memoryStream = new MemoryStream(packet, 0, packet.Length);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            fType = binaryReader.ReadByte();
            fCode = binaryReader.ReadByte();
            fCheckSum = binaryReader.ReadUInt16();
            fUnused = binaryReader.ReadUInt32();
            fData = new byte[packet.Length - FIX_LEN];
            if (fData.Length != 0)
            {
                Array.Copy(packet, 4, fData, 0, fData.Length);
            }
        }

        public List<string> GetList()
        {
            var list = new List<string>();
            list.Add(fType.ToString());
            list.Add(fCode.ToString());
            list.Add(fCheckSum.ToString());
            list.Add(fUnused.ToString());
            list.Add(Encoding.UTF8.GetString(fData));
            return list;
        }
    }
}
