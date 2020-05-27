using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WindowsSniffer {


    public class PacketSniffer
    {
        private const int IP_PACKET_SIZE = 65535;

        private Socket mainSocket;
        private byte[] byteData = new byte[IP_PACKET_SIZE];
        private ReturnPacket returnPacket;
        private volatile bool isContinue = false;
        public bool IsContinue
        {
            set
            {
                isContinue = value;
            }
        }


        public PacketSniffer(ReturnPacket returnPacket)
        {
            this.returnPacket = returnPacket;
        }

        public void StartSniff(String userIpAdress)
        {
            IPAddress iP;
            bool isIp = IPAddress.TryParse(userIpAdress, out iP);
            var socketOptionLevel = iP.AddressFamily == AddressFamily.InterNetwork ? SocketOptionLevel.IP : SocketOptionLevel.IPv6;
            if (isIp)
            {
                try
                {
                    mainSocket = new Socket(iP.AddressFamily, SocketType.Raw, ProtocolType.IP);

                    mainSocket.Bind(new IPEndPoint(iP, 0));
                    mainSocket.SetSocketOption(socketOptionLevel,            //Applies only to IPv4 and IPv6 packets
                                                        SocketOptionName.HeaderIncluded, //Set the include the header
                                                        true);
                    byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4] { 1, 0, 0, 0 }; //Capture outgoing packets

                    //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                    mainSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                                                                                //of Winsock 2
                                            byTrue,
                                            byOut);
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                                new AsyncCallback(Read_Callback), null);


                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "MJsniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

            }
            
        }

       

        public void CloseSocket()
        {
            mainSocket.Close();
        }

        private void Read_Callback(IAsyncResult ar)
        {
            try
            {
                int read = mainSocket.EndReceive(ar);
                returnPacket(byteData, read);
                if (isContinue)
                {
                    byteData = new byte[IP_PACKET_SIZE];
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                        new AsyncCallback(Read_Callback), null);
                }

            }
            catch (ObjectDisposedException)
            {

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "MJsniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
            
    }
}
