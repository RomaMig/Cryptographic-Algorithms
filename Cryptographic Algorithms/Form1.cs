using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Cryptographic_Algorithms
{
    public partial class Form1 : Form
    {
        private User user1, user2;
        private bool user1Active, user2Active;
        private Thread counting;

        public Form1()
        {
            InitializeComponent();
        }

        public struct Message
        {
            public string Sender { get; }
            public TypeMessage type { get; }
            public object[] msg { get; }

            public Message(string sender, TypeMessage type, params object[] msg)
            {
                Sender = sender;
                this.type = type;
                this.msg = msg;
            }

            public override string ToString()
            {
                string message = "";
                switch (type)
                {
                    case Form1.TypeMessage.DEFAULT:
                        message = string.Format(msg.First() as string);
                        break;
                    case Form1.TypeMessage.RSA:
                        message = Utility.arrayToString((BigInteger[])msg.First());
                        break;
                    case Form1.TypeMessage.EL_GAMAL:
                        ElGamal.Cryptogramm cryptogramm = (ElGamal.Cryptogramm)msg.First();
                        message = cryptogramm.a + " " + Utility.arrayToString(cryptogramm.b);
                        break;
                    case Form1.TypeMessage.RSA_KEY:
                        message = ((RSA.Key)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.EL_GAMAL_KEY:
                        message = ((ElGamal.OKey)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.RSA_EDC:
                        message = ((BigInteger)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.EL_GAMAL_EDC:
                        message = ((ElGamal.Sign)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.GOST_EDC:
                        message = ((BigInteger)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.DIFFIE_HELLMAN_MES:
                        message = "mes:" + ((BigInteger)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.MTI_MES:
                        message = "mes1:" + ((BigInteger)msg[0]).ToString() + " mes2:" + ((BigInteger)msg[1]).ToString();
                        break;
                    case Form1.TypeMessage.GOST_KEY:
                        message = ((ГОСТ341094.OKey)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.CHAUMA_KEY:
                        message = ((RSA.Key)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.CHAUMA_MASKED_MSG:
                        message = ((BigInteger)msg.First()).ToString();
                        break;
                    case Form1.TypeMessage.CHAUMA_SIGNED_MASKED_MSG:
                        message = ((BigInteger)msg.First()).ToString();
                        break;
                }
                return String.Format("{0}({1}):\n{2}\n",
                    Sender,
                    (new string[] { "DEFAULT", "RSA", "EL_GAMAL", "RSA_KEY", "EL_GAMAL_KEY", "DIFFIE_HELLMAN_KEY", "RSA_EDC", "EL_GAMAL_EDC", "GOST_EDC", "MTI_MES", "GOST_KEY", "CHAUMA_KEY", "CHAUMA_MASKED_MSG", "CHAUMA_SIGNED_MASKED_MSG" })[(int)type],
                    message);
            }
        }

        public enum TypeMessage
        {
            DEFAULT,
            RSA,
            EL_GAMAL,
            RSA_KEY,
            EL_GAMAL_KEY,
            DIFFIE_HELLMAN_MES,
            RSA_EDC,
            EL_GAMAL_EDC,
            GOST_EDC,
            MTI_MES,
            GOST_KEY,
            CHAUMA_KEY,
            CHAUMA_MASKED_MSG,
            CHAUMA_SIGNED_MASKED_MSG
        }

        public void msgTransfer(User sender, Message msg)
        {
            richTextBox1.Text += msg.ToString();

            if (sender != user1)
            {
                user1.msgReceiving(msg);
            }
            else
            {
                user2.msgReceiving(msg);
            }
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            user1.changeTypeMessage(comboBox1.Text);
            user2.changeTypeMessage(comboBox1.Text);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            user1.createDiffieHellman(BigInteger.Parse(textBox1.Text), BigInteger.Parse(textBox2.Text));
            user2.createDiffieHellman(BigInteger.Parse(textBox1.Text), BigInteger.Parse(textBox2.Text));
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (!user1.isDiffieHellmanExist || !user2.isDiffieHellmanExist)
            {
                button1_Click(this, null);
            }
            user1.startDiffieHellman();
            user2.startDiffieHellman();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (!user1.isDiffieHellmanExist || !user2.isDiffieHellmanExist)
            {
                button1_Click(this, null);
            }
            user1.startMTI();
            user2.startMTI();
        }

        private void startSession_Click(object sender, EventArgs e)
        {
            user1 = new User(this, "User 1");
            user2 = new User(this, "User 2");
            user1Active = true;
            user2Active = true;
            user1.FormClosed += OnUserClosed;
            user2.FormClosed += OnUserClosed;
            user1.Show();
            user2.Show();
            user1.Init();
            user2.Init();
            numericUpDown1_ValueChanged(this, null);
            numericUpDown2_ValueChanged(this, null);
            OnOff(true);
        }

        private void numericUpDown1_ValueChanged(object sender, EventArgs e)
        {
            user1?.changeBlock((int)numericUpDown1.Value);
            user2?.changeBlock((int)numericUpDown1.Value);
        }

        private void numericUpDown2_ValueChanged(object sender, EventArgs e)
        {
            user1?.changeCodesize((int)numericUpDown2.Value);
            user2?.changeCodesize((int)numericUpDown2.Value);
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
            if (!char.IsControl(e.KeyChar) && !char.IsDigit(e.KeyChar) && e.KeyChar != 8 && e.KeyChar != 44)
                e.Handled = true;
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (counting != null && counting.IsAlive) return;
            string[] args = textBox3.Text.Split(',');
            switch (comboBox2.Text)
            {
                case "pow":
                    counting = new Thread(
                        () =>
                        {
                            if (args.Length < 2)
                            {
                                toolStripStatusLabel1.Text = "Не хватает аргументов";
                                return;
                            }
                            toolStripStatusLabel1.Text = "Вычисление...";
                            richTextBox2.Text += string.Format("{0}({1},{2})={3}\n", comboBox2.Text, args[0], args[1], Algorithms.pow(BigInteger.Parse(args[0]), BigInteger.Parse(args[1])));
                            toolStripStatusLabel1.Text = "Готово";
                        });
                    break;
                case "pow_mod":
                    counting = new Thread(
                        () =>
                        {
                            if (args.Length < 3)
                            {
                                toolStripStatusLabel1.Text = "Не хватает аргументов";
                                return;
                            }
                            toolStripStatusLabel1.Text = "Вычисление...";
                            richTextBox2.Text += string.Format("{0}({1},{2},{3})={4}\n", comboBox2.Text, args[0], args[1], args[2], Algorithms.pow_mod(BigInteger.Parse(args[0]), BigInteger.Parse(args[1]), BigInteger.Parse(args[2])));
                            toolStripStatusLabel1.Text = "Готово";
                        });
                    break;
                case "gcdex":
                    counting = new Thread(
                        () =>
                        {
                            if (args.Length < 2)
                            {
                                toolStripStatusLabel1.Text = "Не хватает аргументов";
                                return;
                            }
                            toolStripStatusLabel1.Text = "Вычисление...";
                            richTextBox2.Text += string.Format("{0}({1},{2})={3}\n", comboBox2.Text, args[0], args[1], Algorithms.gcdex(BigInteger.Parse(args[0]), BigInteger.Parse(args[1])));
                            toolStripStatusLabel1.Text = "Готово";
                        });
                    break;
                case "get_prime":
                    counting = new Thread(
                        () =>
                        {
                            if (args.Length < 1)
                            {
                                toolStripStatusLabel1.Text = "Не хватает аргументов";
                                return;
                            }
                            toolStripStatusLabel1.Text = "Вычисление...";
                            richTextBox2.Text += string.Format("{0}({1})={2}\n", comboBox2.Text, args[0], Utility.getRandomPrime(Int32.Parse(args[0])));
                            toolStripStatusLabel1.Text = "Готово";
                        });
                    break;
                default:
                    toolStripStatusLabel1.Text = "Такой функции не найдено";
                    return;
            }
            counting.Start();
        }

        private void button5_Click(object sender, EventArgs e)
        {
            counting?.Abort();
            toolStripStatusLabel1.Text = "Вычисление прервано";
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            counting?.Abort();
            toolStripStatusLabel1.Text = "Вычисление прервано";
        }

        private void richTextBox2_TextChanged(object sender, EventArgs e)
        {
            richTextBox2.SelectionStart = richTextBox2.Text.Length;
            richTextBox2.ScrollToCaret();
        }

        private void richTextBox1_TextChanged(object sender, EventArgs e)
        {
            richTextBox1.SelectionStart = richTextBox1.Text.Length;
            richTextBox1.ScrollToCaret();
        }

        private void OnUserClosed(object sender, EventArgs args)
        {
            User user = sender as User;
            if (user == user1)
            {
                user1Active = false;
            }
            else
            {
                user2Active = false;
            }

            if (user1Active)
            {
                user1.Close();
                user1 = null;
            }
            if (user2Active)
            {
                user2.Close();
                user2 = null;
            }

            OnOff(false);
        }

        private void OnOff(bool state)
        {
            comboBox1.Enabled = state;
            button1.Enabled = state;
            button2.Enabled = state;
            button3.Enabled = state;
            startSession.Enabled = !state;
        }
    }
}
