using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WindowsSniffer
{
    class PacketAnalizer
    {
        private const int IPv4Protocol = 4;
        private const int IPv6Protocol = 6;
        private const int PROTOCOL_IPv4 = 9;

        private volatile string fFilter = "All";

        public string Filter
        {
            set
            {
                fFilter = value;
            }
        }

        public List<string> AnalizePacket(byte[] packet, int received)
        {
            var version = packet[0]  >> 4;
            List<string> list = null; 

            switch (version )
            {
                case IPv4Protocol:
                    IPv4ProtocolParser pv4ProtocolParser = new IPv4ProtocolParser(packet, received);
                    list = pv4ProtocolParser.MakeList();
                    if (fFilter != "All" && fFilter != list[PROTOCOL_IPv4])
                    {
                        list = null;
                    }
                    break;
                case IPv6Protocol:
                    IPv6Parser pv6Parser = new IPv6Parser(packet, received);
                    list = pv6Parser.MakeBaseIPv6List();
                    break;
                    
            }
            return list;
        }
    }
}
