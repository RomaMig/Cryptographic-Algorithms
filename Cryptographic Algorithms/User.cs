using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Cryptographic_Algorithms
{
    public partial class User : Form
    {
        public bool isDiffieHellmanExist { get; private set; }
        private string Sender { get => signTextBox.Text == "" ? this.Text : signTextBox.Text; }
        private Form1 host;
        private Form1.TypeMessage typeMessage;
        private Form1.TypeMessage typeEDS;
        private RSA.Key RSA_ok, RSA_ck;
        private ElGamal.OKey ElGamal_ok;
        private ElGamal.CKey ElGamal_ck;
        private ГОСТ341094.OKey GOST_EDS_ok;
        private ГОСТ341094.CKey GOST_EDS_ck;
        private DiffieHellman.Key DiffieHellman_ok;
        private BigInteger DiffieHellman_ck;
        private BigInteger DiffieHellman_MTI_ck;
        private RSA.Key Chauma_ok;
        private RSA.Key Chauma_ck;
        private Chauma.Key Chauma_k;
        private BigInteger signedMsg;
        private RSA.Key alien_RSA_ok;
        private ElGamal.OKey alien_ElGamal_ok;
        private ГОСТ341094.OKey alien_GOST_EDS_ok;
        private RSA.Key alien_Chauma_ok;
        private int block;
        private int codesize;
        private bool isInit;

        public User(Form1 host, string name)
        {
            InitializeComponent();
            this.Text = name;
            this.host = host;
            signTextBox.Text = name;
            typeMessage = Form1.TypeMessage.DEFAULT;
            typeEDS = Form1.TypeMessage.DEFAULT;
            block = 2;
            codesize = 16;
            isDiffieHellmanExist = false;
            isInit = false;
        }

        public void Init()
        {
            button1_Click(this, null);
            button2_Click(this, null);
            button3_Click(this, null);
            button5_Click(this, null);
            isInit = true;
            updateInfo();
        }

        public void createRSA(BigInteger p, BigInteger q)
        {
            RSA.getKeys(p, q, out RSA_ok, out RSA_ck);

            label4.Text = RSA_ok.key.ToString();
            label5.Text = RSA_ck.key.ToString();
            label6.Text = RSA_ok.N.ToString();

            sendMessage(Form1.TypeMessage.RSA_KEY, RSA_ok);
        }
        public void createChauma(BigInteger p, BigInteger q)
        {
            Chauma.getKeys(p, q, out Chauma_ok, out Chauma_ck, out Chauma_k);

            label42.Text = Chauma_ok.key.ToString();
            label41.Text = Chauma_ck.key.ToString();
            label39.Text = Chauma_ck.N.ToString();
            label45.Text = Chauma_k.k.ToString();
            label47.Text = Chauma_k.rk.ToString();

            sendMessage(Form1.TypeMessage.CHAUMA_KEY, Chauma_ok);
        }

        public void createElGamal(BigInteger p)
        {
            ElGamal.getKeys(p, out ElGamal_ok, out ElGamal_ck);

            label13.Text = ElGamal_ok.g.ToString();
            label11.Text = ElGamal_ok.y.ToString();
            label17.Text = ElGamal_ck.x.ToString();

            sendMessage(Form1.TypeMessage.EL_GAMAL_KEY, ElGamal_ok);
        }

        public void createGOST(int bits)
        {
            ГОСТ341094.getKeys(bits, out GOST_EDS_ok, out GOST_EDS_ck);

            label14.Text = GOST_EDS_ok.p.ToString();
            label23.Text = GOST_EDS_ok.q.ToString();
            label21.Text = GOST_EDS_ok.a.ToString();
            label16.Text = GOST_EDS_ok.y.ToString();
            label26.Text = GOST_EDS_ok.r.ToString();

            sendMessage(Form1.TypeMessage.GOST_KEY, GOST_EDS_ok);
        }

        public BigInteger createRSA_EDS(string sign)
        {
            return RSA.getEDS(sign, RSA_ok, RSA_ck, block, codesize);
        }

        public ElGamal.Sign createElGamal_EDS(string sign)
        {
            return ElGamal.getEDS(sign, ElGamal_ok, ElGamal_ck, block, codesize);
        }

        public BigInteger createGOST_EDS(string sign)
        {
            return ГОСТ341094.getEDS(sign, GOST_EDS_ok, GOST_EDS_ck, block, codesize);
        }

        public void createDiffieHellman(BigInteger p, BigInteger a)
        {
            DiffieHellman.getKey(p, a, out DiffieHellman_ok);

            label32.Text = DiffieHellman_ok.key.ToString();
            label30.Text = DiffieHellman_ok.a.ToString();
            isDiffieHellmanExist = true;
            updateInfo();
        }

        public void msgReceiving(Form1.Message msg)
        {
            string message = "";
            switch (msg.type)
            {
                case Form1.TypeMessage.DEFAULT:
                    message = string.Format("{0}: {1}\n", msg.Sender, msg.msg.First() as string);
                    break;
                case Form1.TypeMessage.RSA:
                    message = string.Format("{0}: {1}\n", msg.Sender, RSA.decrypt((BigInteger[])msg.msg.First(), RSA_ck, codesize));
                    break;
                case Form1.TypeMessage.EL_GAMAL:
                    message = string.Format("{0}: {1}\n", msg.Sender, ElGamal.decrypt((ElGamal.Cryptogramm)msg.msg.First(), ElGamal_ck, codesize));
                    break;
                case Form1.TypeMessage.RSA_KEY:
                    alien_RSA_ok = (RSA.Key)msg.msg.First();
                    return;
                case Form1.TypeMessage.EL_GAMAL_KEY:
                    alien_ElGamal_ok = (ElGamal.OKey)msg.msg.First();
                    return;
                case Form1.TypeMessage.GOST_KEY:
                    alien_GOST_EDS_ok = (ГОСТ341094.OKey)msg.msg.First();
                    break;
                case Form1.TypeMessage.RSA_EDC:
                    message += RSA.EDSVerification(msg.Sender, (BigInteger)msg.msg.First(), alien_RSA_ok, block, codesize) ? "✓ " : "× ";
                    break;
                case Form1.TypeMessage.EL_GAMAL_EDC:
                    message += ElGamal.EDSVerification(msg.Sender, (ElGamal.Sign)msg.msg.First(), alien_ElGamal_ok, block, codesize) ? "✓ " : "× ";
                    break;
                case Form1.TypeMessage.GOST_EDC:
                    message += ГОСТ341094.EDSVerification(msg.Sender, (BigInteger)msg.msg.First(), alien_GOST_EDS_ok, block, codesize) ? "✓ " : "× ";
                    break;
                case Form1.TypeMessage.DIFFIE_HELLMAN_MES:
                    DiffieHellman_ck = DiffieHellman.DiffieHellmanCommonKey((BigInteger)msg.msg.First(), DiffieHellman_ok);
                    label34.Text = DiffieHellman_ck.ToString();
                    updateInfo();
                    break;
                case Form1.TypeMessage.MTI_MES:
                    DiffieHellman_MTI_ck = DiffieHellman.MTICommonKey((BigInteger)msg.msg[0], (BigInteger)msg.msg[1], DiffieHellman_ok);
                    label36.Text = DiffieHellman_MTI_ck.ToString();
                    updateInfo();
                    break;
                case Form1.TypeMessage.CHAUMA_KEY:
                    alien_Chauma_ok = (RSA.Key)msg.msg.First();
                    return;
                case Form1.TypeMessage.CHAUMA_MASKED_MSG:
                    sendMessage(Form1.TypeMessage.CHAUMA_SIGNED_MASKED_MSG, Chauma.getSignedMaskedMessage((BigInteger)msg.msg.First(), Chauma_ck));
                    return;
                case Form1.TypeMessage.CHAUMA_SIGNED_MASKED_MSG:
                    signedMsg = Chauma.getSignedMessage((BigInteger)msg.msg.First(), alien_Chauma_ok, Chauma_k);
                    label49.Text = signedMsg.ToString();
                    updateInfo();
                    return;
            }
            msgRichTextBox.Text += message;
        }

        private void send_Click(object sender, EventArgs e)
        {
            Task.Run(() =>
            {
                msgRichTextBox.Text += string.Format("Вы: {0}\n", msgSendRichTextBox.Text);

                switch (typeEDS)
                {
                    case Form1.TypeMessage.RSA_EDC:
                        sendMessage(typeEDS, createRSA_EDS(Sender));
                        break;
                    case Form1.TypeMessage.EL_GAMAL_EDC:
                        sendMessage(typeEDS, createElGamal_EDS(Sender));
                        break;
                    case Form1.TypeMessage.GOST_EDC:
                        sendMessage(typeEDS, createGOST_EDS(Sender));
                        break;
                    default:
                        break;
                }

                switch (typeMessage)
                {
                    case Form1.TypeMessage.DEFAULT:
                        sendMessage(typeMessage, msgSendRichTextBox.Text);
                        break;
                    case Form1.TypeMessage.RSA:
                        sendMessage(typeMessage, RSA.encrypt(msgSendRichTextBox.Text, alien_RSA_ok, block, codesize));
                        break;
                    case Form1.TypeMessage.EL_GAMAL:
                        sendMessage(typeMessage, ElGamal.encrypt(msgSendRichTextBox.Text, alien_ElGamal_ok, block, codesize));
                        break;
                }

                msgSendRichTextBox.Text = "";
            });
        }

        private void button4_Click(object sender, EventArgs e)
        {
            sendMessage(Form1.TypeMessage.CHAUMA_MASKED_MSG, Chauma.getMaskedMessage(richTextBox2.Text, alien_Chauma_ok, Chauma_k, block, codesize));
        }

        private Form1.Message sendMessage(Form1.TypeMessage type, params object[] args)
        {
            lock (host)
            {
                Form1.Message msg = new Form1.Message(Sender, type, args);
                host.msgTransfer(this, msg);
                return msg;
            }
        }

        public void startDiffieHellman()
        {
            sendMessage(Form1.TypeMessage.DIFFIE_HELLMAN_MES, DiffieHellman.DiffieHellmanMES(DiffieHellman_ok));
        }

        public void startMTI()
        {
            BigInteger mes1, mes2;
            DiffieHellman.MTIMES(DiffieHellman_ok, out mes1, out mes2);
            sendMessage(Form1.TypeMessage.MTI_MES, mes1, mes2);
        }

        public void changeBlock(int block)
        {
            this.block = block;
        }

        public void changeCodesize(int codesize)
        {
            this.codesize = codesize;
        }

        public void changeTypeMessage(string type)
        {
            switch (type)
            {
                case "RSA":
                    typeMessage = Form1.TypeMessage.RSA;
                    break;
                case "El Gamal":
                    typeMessage = Form1.TypeMessage.EL_GAMAL;
                    break;
                default:
                    typeMessage = Form1.TypeMessage.DEFAULT;
                    break;
            }
        }

        private void SelectEDS(object sender, EventArgs e)
        {
            switch (comboBoxEDS.Text)
            {
                case "RSA EDS":
                    typeEDS = Form1.TypeMessage.RSA_EDC;
                    break;
                case "El Gamal EDS":
                    typeEDS = Form1.TypeMessage.EL_GAMAL_EDC;
                    break;
                case "ГОСТ 34.10-94 ЭЦП":
                    typeEDS = Form1.TypeMessage.GOST_EDC;
                    break;
                default:
                    typeEDS = Form1.TypeMessage.DEFAULT;
                    break;
            }
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            await Task.Run(() =>
            {
                createRSA(BigInteger.Parse(textBox1.Text), BigInteger.Parse(textBox2.Text));
                updateInfo();
            });
        }

        private async void button2_Click(object sender, EventArgs e)
        {
            await Task.Run(() =>
            {
                createElGamal(BigInteger.Parse(textBox3.Text));
                updateInfo();
            });
        }

        private async void button3_Click(object sender, EventArgs e)
        {
            await Task.Run(() =>
            {
                createGOST(Int32.Parse(textBox4.Text));
                updateInfo();
            });
        }

        private async void button5_Click(object sender, EventArgs e)
        {
            await Task.Run(() =>
            {
                createChauma(BigInteger.Parse(textBox6.Text), BigInteger.Parse(textBox5.Text));
                updateInfo();
            });
        }

        private void textBox1_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (!char.IsControl(e.KeyChar) && !char.IsDigit(e.KeyChar) && e.KeyChar != 8)
                e.Handled = true;
        }

        private void textBox2_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (!char.IsControl(e.KeyChar) && !char.IsDigit(e.KeyChar) && e.KeyChar != 8)
                e.Handled = true;
        }

        private void textBox3_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (!char.IsControl(e.KeyChar) && !char.IsDigit(e.KeyChar) && e.KeyChar != 8)
                e.Handled = true;
        }

        private void textBox4_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (!char.IsControl(e.KeyChar) && !char.IsDigit(e.KeyChar) && e.KeyChar != 8)
                e.Handled = true;
        }

        private void msgRichTextBox_TextChanged(object sender, EventArgs e)
        {
            msgRichTextBox.SelectionStart = msgRichTextBox.Text.Length;
            msgRichTextBox.ScrollToCaret();
        }

        private void button6_Click(object sender, EventArgs e)
        {
            MessageBox.Show(RSA.EDSVerification(richTextBox2.Text, signedMsg, alien_Chauma_ok) ? "Подпись верна" : "Подпись неверна");
        }

        public void updateInfo()
        {
            if (!isInit) return;

            string info = "";
            info += string.Format("RSA:\nKo:\n{0}\nKc:\n{1}\nN:\n{2}\nKo другого пользователя:\n{3}\nN другого пользователя:\n{4}\n", RSA_ok.key, RSA_ck.key, RSA_ok.N, alien_RSA_ok.key, alien_RSA_ok.N);
            info += "-----------------------------\n";
            info += string.Format("El Gamal:\nG:\n{0}\nY:\n{1}\nX:\n{2}\nG другого пользователя:\n{3}\nY другого пользователя:\n{4}\n", ElGamal_ok.g, ElGamal_ok.y, ElGamal_ck.x, alien_ElGamal_ok.g, alien_ElGamal_ok.y);
            info += "-----------------------------\n";
            info += string.Format("ГОСТ Р34.10-94:\np:\n{0}\nq:\n{1}\na:\n{2}\ny:\n{3}\nr:\n{4}\np другого пользователя:\n{5}\nq другого пользователя:\n{6}\na другого пользователя:\n{7}\ny другого пользователя:\n{8}\nr другого пользователя:\n{9}\n", GOST_EDS_ok.p, GOST_EDS_ok.q, GOST_EDS_ok.a, GOST_EDS_ok.y, GOST_EDS_ok.r, alien_GOST_EDS_ok.p, alien_GOST_EDS_ok.q, alien_GOST_EDS_ok.a, alien_GOST_EDS_ok.y, alien_GOST_EDS_ok.r);
            info += "-----------------------------\n";
            info += string.Format("Диффи-Хеллман:\nx:\n{0}\na:\n{1}\nКлюч по схеме Диффи-Хеллмана:\n{2}\nКлюч по схеме Диффи-Хеллмана с протоколом MTI:\n{3}\n",
                DiffieHellman_ok.key, DiffieHellman_ok.a, DiffieHellman_ck, DiffieHellman_MTI_ck);
            info += "-----------------------------\n";
            info += string.Format("Чаума:\nKo:\n{0}\nKc:\n{1}\nN:\n{2}\nk:\n{3}\nk^-1:\n{4}\nKo другого пользователя:\n{5}\nN другого пользователя:\n{6}\nПодписанное другим пользователем сообщение:\n{7}\n", Chauma_ok.key, Chauma_ck.key, Chauma_ck.N, Chauma_k.k, Chauma_k.rk, alien_Chauma_ok.key, alien_Chauma_ok.N, signedMsg);
            info += "-----------------------------\n";
            richTextBox1.Text = info;
        }
    }
}
