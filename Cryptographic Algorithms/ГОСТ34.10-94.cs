using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Cryptographic_Algorithms
{
    static class ГОСТ341094
    {
        public const int BLOCK = 2; //длинна блока по умолчанию
        public const int CODESIZE = 16; //размер кодировки по умолчанию

        /**
         * Описание открытого ключа
         */
        public struct OKey
        {
            public BigInteger p { get; }
            public BigInteger q { get; }
            public BigInteger y { get; }
            public BigInteger a { get; }
            public BigInteger r { get; }

            public OKey(BigInteger p, BigInteger q, BigInteger y, BigInteger a, BigInteger r)
            {
                this.p = p;
                this.q = q;
                this.y = y;
                this.a = a;
                this.r = r;
            }

            public override string ToString()
            {
                return string.Format("p:{0} q:{1} y:{2} a:{3} r:{4}", p, q, y, a, r);
            }
        }

        /**
         * Описание закрытого ключа
         */
        public struct CKey
        {
            public BigInteger x { get; }
            public BigInteger k { get; }

            public CKey(BigInteger x, BigInteger k)
            {
                this.x = x;
                this.k = k;
            }
        }

        /**
         * Интерфейсы взаимодействия с классом по умолчанию
         */
        public static BigInteger Hash(string msg, BigInteger y, BigInteger p, BigInteger q)
        {
            return Hash(msg, y, p, q, BLOCK, CODESIZE);
        }

        public static BigInteger getEDS(string msg, OKey ok, CKey ck)
        {
            return getEDS(msg, ok, ck);
        }

        public static bool EDSVerification(string msg, BigInteger s, OKey oKey)
        {
            return EDSVerification(msg, s, oKey, BLOCK, CODESIZE);
        }

        /**
         * Функция генерирования ключей
         */
        public static void getKeys(int bits, out OKey oKey, out CKey cKey)
        {
            BigInteger p;
            BigInteger q;
            getRandomPQ(bits, out p, out q);    //получаем случайные p и q
            BigInteger a = getRandomA(p, q);    //получение параметра
            BigInteger x = Utility.RandomIntegerBelow(q - 1) + 1;   //случайное число меньшее q-1
            BigInteger y = Algorithms.pow_mod(a, x, p); //получаем y

            BigInteger k;
            BigInteger r;

            do
            {
                k = Utility.RandomIntegerBelow(q - 1) + 1;  //вычисляем k
            } while ((r = Algorithms.pow_mod(a, k, p) % q) == 0);   //если не удовлетворяет условию, получаем k по новой

            oKey = new OKey(p, q, y, a, r);
            cKey = new CKey(x, k);
        }

        /**
         * Функция хеширования сообщения
         */
        public static BigInteger Hash(string msg, BigInteger y, BigInteger p, BigInteger q, int block, int codesize)
        {
            BigInteger[] text = Utility.msgToBlock(msg, block, codesize);  //разбиваем сообщение на блоки

            BigInteger m = 0;
            for (int i = 0; i < text.Length; i++)
            {
                m ^= Algorithms.pow_mod(text[i], y, p);
                m %= p;
            }
            return m % q == 0 ? 1 : m;  //если кратно q, то возвращаем 1
        }

        /**
         * Функция получения подписи
         */
        public static BigInteger getEDS(string msg, OKey ok, CKey ck, int block, int codesize)
        {
            BigInteger s = (ck.x * ok.r + ck.k * Hash(msg, ok.y, ok.p, ok.q, block, codesize)) % ok.q;
            return s;
        }

        /**
         * Функция проверки подписи
         */
        public static bool EDSVerification(string msg, BigInteger s, OKey oKey, int block, int codesize)
        {
            BigInteger m = Hash(msg, oKey.y, oKey.p, oKey.q, block, codesize);
            BigInteger v = Algorithms.pow_mod(m, oKey.q - 2, oKey.q);
            BigInteger z1 = (s * v) % oKey.q;
            BigInteger z2 = ((oKey.q - oKey.r) * v) % oKey.q;
            BigInteger u = (Algorithms.pow_mod(oKey.a, z1, oKey.p) * Algorithms.pow_mod(oKey.y, z2, oKey.p) % oKey.p) % oKey.q;
            return u == oKey.r;
        }

        /**
         * Функция получения больших простых p и q, где q делитель p - 1
         * принимаем размер p в битах
         */
        public static void getRandomPQ(int bits, out BigInteger outp, out BigInteger outq)
        {
            BigInteger m216 = Algorithms.pow(2, 16);
            BigInteger[] t = new BigInteger[(int)Math.Ceiling(Math.Log(bits, 2)) - 3];
            t[0] = bits;
            for (int i = 1; i < t.Length; i++)
            {
                t[i] = Algorithms.pow(2, t.Length + 3 - i);
            }
            BigInteger[] p = new BigInteger[t.Length];
            int x0 = Utility.rnd.Next();
            int c = Utility.rnd.Next();
            c = c % 2 == 0 ? c + 1 : c;
            BigInteger y0 = x0;
            int s = t.Length - 1;
            for (p[s] = Algorithms.pow(2, 15); !Utility.isPrime(p[s]); p[s]++) ;
            for (int m = s - 1; m >= 0; m--)
            {
                int rm = (int)Math.Ceiling((decimal)(t[m + 1] / 16));
            //m1:
                BigInteger[] y = new BigInteger[rm + 1];
                y[0] = y0;
                for (int i = 1; i <= rm; i++)
                {
                    y[i] = (19381 * y[i - 1] + c) % m216;
                }
                BigInteger Ym = 0;
                BigInteger m2tm = Algorithms.pow(2, t[m] - 16);
                for (int i = 0; i < rm; i++)
                {
                    Ym += y[i] * m2tm;
                }
                y0 = y[rm];
                BigInteger m2tm1 = Algorithms.pow(2, t[m] - 1);
                BigInteger N = m2tm1 / p[m + 1] + m2tm1 * Ym / p[m + 1] / Algorithms.pow(2, 16 * rm);
                N = N % 2 == 0 ? N : N + 1;
                int k = 0;
                do
                {
                    p[m] = p[m + 1] * (N + k) + 1;
                    //if (p[m] > Algorithms.pow(2, t[m]))
                    //    goto m1;
                    k += 2;
                } while (!(Algorithms.pow_mod(2, p[m + 1] * (N + k - 2), p[m]) == 1 && Algorithms.pow_mod(2, N + k - 2, p[m]) != 1));
            }
            outp = p[0];
            outq = p[1];
        }

        /**
         * Функция генерация параметра а по заданным p и q
         */
        private static BigInteger getRandomA(BigInteger p, BigInteger q)
        {
            BigInteger d = Utility.RandomIntegerBelow(p - 3) + 2;
            BigInteger x = (p - 1) / q;
            BigInteger f;
            for (BigInteger i = d; i > 1; i--)
            {
                if ((f = Algorithms.pow_mod(i, x, p)) != 1) return f;
            }
            for (BigInteger i = d + 1; i < p - 2; i++)
            {
                if ((f = Algorithms.pow_mod(i, x, p)) != 1) return f;
            }
            throw new Exception("Problems with a");
        }

        /*
        private static BigInteger getRandomQ(BigInteger p)
        {
            BigInteger q = Utility.RandomIntegerBelow(p - 2) + 2;
            for (BigInteger i = q; i < p - 1; i++)
            {
                if ((p - 1) % i == 0) if (Utility.isPrime(i))
                        return i;
            }
            for (BigInteger i = q - 1; i >= 3; i--)
            {
                if ((p - 1) % i == 0) if (Utility.isPrime(i)) return i;
            }
            throw new Exception("Problems with q");
        }

        private static BigInteger getRandomA(BigInteger p, BigInteger q)
        {
            BigInteger a = Utility.RandomIntegerBelow(p - 2) + 1;
            for (BigInteger i = a; i < p - 1; i++)
            {
                if (Algorithms.pow_mod(i, q, p) == 1) return i;
            }
            for (BigInteger i = a - 1; i >= 1; i--)
            {
                if (Algorithms.pow_mod(i, q, p) == 1) return i;
            }
            throw new Exception("Problems with a");
        }
        */
    }
}
