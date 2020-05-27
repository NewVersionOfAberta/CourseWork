using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WindowsSniffer
{
    public delegate int ReturnPacket(byte[] p, int nReceived); 


    public partial class fmSniffer : Form
    {
        private const int MAX_PACKET = 100;
        ViewMaker viewMaker = new ViewMaker();

        delegate void DelegateShow(List<string> packet);
        private DelegateShow delegateShow;
        private PacketSniffer ps;
        private bool isContinue = false;
        private List<List<string>> packets = new List<List<string>>();
        PacketAnalizer packetAnalizer = new PacketAnalizer();

        public fmSniffer()
        {
            InitializeComponent();
        }


        private void ShowPacket(List<string> packet)
        {
            try
            {
                if (lvPackets.Items.Count > MAX_PACKET)
                {
                    lvPackets.Items.RemoveAt(0);
                }
                string simpleStr = viewMaker.MakeSimple(packet);
                if (simpleStr == null)
                {
                    simpleStr = "Протокол: Не поддерживается";
                }
                lvPackets.Items.Add(simpleStr);
            }catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "MJsniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

        }

        private int RecievePacket(byte[] packet, int nReceived)
        {

            
            var packetList = packetAnalizer.AnalizePacket(packet, nReceived);
            if (packets.Count > 100)
            {
                packets.RemoveAt(0);   
            }
            if (packetList != null)
            {
                packets.Add(packetList);
                lvPackets.Invoke(delegateShow, packetList);
            }
           
            return 0;

        }

        public string[] GetIps()
        {
            IPHostEntry HosyEntry = Dns.GetHostEntry(Dns.GetHostName());
            string strIP = null;
            List<string> ls = new List<string>();
            if (HosyEntry.AddressList.Length > 0)
            {
                foreach (IPAddress ip in HosyEntry.AddressList)
                {
                   
                    strIP = ip.ToString();
                    ls.Add(strIP);
                    
                }
            }
            return ls.ToArray();
        }

        public void fillFilters()
        {
            string[] filters = { 
                  "All",
                  "ICMP",
                  "Gateway-to-Gateway",
                  "CMCC Gateway Monitoring Message",
                  "ST",
                  "TCP",
                  "UCL",
                  "Secure",
                  "BBN RCC Monitoring",
                  "NVP",
                  "PUP",
                  "Pluribus",
                  "Telenet",
                  "XNET",
                  "Chaos",
                  "UDP",
                  "Multiplexing",
                  "DCN",
                  "TAC Monitoring",
                  "any local network",
                  "SATNET and Backroom EXPAK",
                  "MIT Subnet Support",
                  "SATNET Monitoring",
                  "Internet Packet Core Utility",
                  "Backroom SATNET Monitoring",
                  "WIDEBAND Monitoring ",
                  "WIDEBAND EXPAK"
            };
            cbProtocol.Items.AddRange(filters);
            cbProtocol.SelectedIndex = 0;
        }

        private void btnProccess_Click(object sender, EventArgs e)
        {
            if (!isContinue)
            {
                btnProccess.Text = "&Стоп";
                delegateShow = new DelegateShow(ShowPacket);
                ReturnPacket returnPacket = new ReturnPacket(RecievePacket);
                ps = new PacketSniffer(returnPacket);
                ps.StartSniff(cbIP.Text);
                
            }
            else
            {
                btnProccess.Text = "&Начать";
                ps.CloseSocket();
            }
            isContinue = !isContinue;
            ps.IsContinue = isContinue;
            cbIP.Enabled = !cbIP.Enabled;

        }

        private void fmSniffer_Load(object sender, EventArgs e)
        {
            string[] ips = GetIps();
            IPAddress tempIP;
            fillFilters();
            if (ips.Length > 0)
            {
                foreach (string temp in ips)
                {
                    if (IPAddress.TryParse(temp, out tempIP))
                    {
                        cbIP.Items.Add(temp);
                    }
                }
                cbIP.SelectedIndex = 0;
            }
            
        }

        private void fmSniffer_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (isContinue)
            {
                ps.CloseSocket();
            }
        }

        private void FillGrid(List<string> values)
        { 
            List<string>[] extDescribe = viewMaker.MakeExtendList(values);
            try
            {
                for (int i = 0; i < values.Count - 1; i++)
                {
                    dgvExtPacket.Rows.Add();
                    dgvExtPacket[0, i].Value = extDescribe[0][i];
                    dgvExtPacket[1, i].Value = values[i];
                    dgvExtPacket[2, i].Value = extDescribe[1][i];
                }

                rtbData.Text = values[values.Count - 1].Replace('\0', ' ');
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "MJsniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }


        private void lvPackets_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (lvPackets.SelectedItems.Count > 0)
            {
                int selectedItemIndex = lvPackets.SelectedItems[0].Index;
                if (selectedItemIndex < packets.Count)
                {
                    dgvExtPacket.Rows.Clear();
                    FillGrid(packets.ElementAt(selectedItemIndex));
                }
            }
        }

        private void cbProtocol_SelectedIndexChanged(object sender, EventArgs e)
        {
            lvPackets.Items.Clear();
            dgvExtPacket.Rows.Clear();
            packetAnalizer.Filter = cbProtocol.Text;

        }
    }
}
