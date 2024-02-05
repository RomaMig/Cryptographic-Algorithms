using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Cryptographic_Algorithms
{
    static class Utility
    {
        public static Random rnd;

        static Utility()
        {
            rnd = new Random();
        }

        /**
         * Функция производящая декодировку разбитого по блокам сообщения
         * На вход подаются блоки []text и размер кодировки codesize
         * возвращяется декодированное сообщение
         */
        public static string blockToMsg(BigInteger[] text, int codesize)
        {
            string msg = "";  //строка, в которую записывается результат декодировки
            int mask = 0;   //маска, выделяющая кол-во битов под размер кодировки

            //Создание маски
            for (int i = 0; i < codesize; i++)
            {
                mask <<= 1;
                mask |= 1;
            }
            //проход по блокам
            for (int i = 0; i < text.Length; i++)
            {
                string tmp = ""; //буфферная строка
                while (text[i] > 0) //пока блок не кончится
                {
                    tmp = (char)(text[i] & mask) + tmp; //записываем последний символ блока в начало буфферной строки
                    text[i] >>= codesize; //сдвигаем блок
                }
                msg += tmp;  //сохраняем декодированный блок
            }
            return msg; //возвращяем декодированное сообщение
        }

        /**
         * Функция производящая сжатие и разбивку сообщения по блокам заданной длинны с обозначеным размером кодировки
         * На вход подается сообщение msg, длинна блока block и размер кодировки codesize
         * возвращается набор блоков закодированного сообщения
         */
        public static BigInteger[] msgToBlock(string msg, int block, int codesize)
        {
            BigInteger[] textBlock = new BigInteger[(int)Math.Ceiling(((float)msg.Length) / block)];  //выделение памяти под массив блоков

            //проходимся по сообщению, деля его на блоки
            for (int i = 0; i < textBlock.Length; i++)
            {
                textBlock[i] = 0;   //обнуляем значение блока
                for (int j = i * block; j < i * block + block && j < msg.Length; j++)
                {
                    textBlock[i] <<= codesize; //сдвигаем блок на размер кодировки
                    textBlock[i] |= msg[j]; //записываем текущий символ
                }
            }
            return textBlock; //возвращаем набор блоков
        }

        public static BigInteger getRandomKey(BigInteger n)
        {
            BigInteger start = RandomIntegerBelow(n);
            for (BigInteger i = start; i <= n; i++)
            {
                if (Algorithms.gcdex(i, n) != -1)
                {
                    return i;
                }
            }
            for (BigInteger i = start - 1; i > 0; i--)
            {
                if (Algorithms.gcdex(i, n) != -1)
                {
                    return i;
                }
            }
            throw new Exception("Problems with key");
        }

        public static BigInteger getRandomPrime(int bits)
        {
            if (bits <= 32)
                return getRandomPrimeSmall(bits);
            return getRandomPrimeBig(bits);
        }

        public static BigInteger getRandomPrimeSmall(int bits)
        {
            BigInteger m2b = Algorithms.pow(2, bits);
            BigInteger m2b1 = Algorithms.pow(2, bits - 1);
            BigInteger p = RandomIntegerBelow(m2b1) + m2b1;

            for (BigInteger i = p; i < m2b; i++)
            {
                if (Utility.isPrime(i))
                    return i;
            }
            for (BigInteger i = p - 1; i > m2b1; i--)
            {
                if (Utility.isPrime(i))
                    return i;
            }
            throw new Exception("Problems with prime number");
        }

        public static BigInteger getRandomPrimeBig(int bits)
        {
            BigInteger m216 = Algorithms.pow(2, 16);
            BigInteger[] t = new BigInteger[(int)Math.Ceiling(Math.Log(bits, 2)) - 3];
            t[0] = bits;
            for (int i = 1; i < t.Length; i++)
            {
                t[i] = Algorithms.pow(2, t.Length + 3 - i);
            }
            BigInteger[] p = new BigInteger[t.Length];
            int x0 = rnd.Next();
            int c = rnd.Next();
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
            return p[0];
        }

        public static BigInteger RandomIntegerBelow(BigInteger N)
        {
            byte[] bytes = N.ToByteArray();
            BigInteger R;

            do
            {
                rnd.NextBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)0x7F; //force sign bit to positive
                R = new BigInteger(bytes);
            } while (R >= N);

            return R;
        }

        public static BigInteger Sqrt(this BigInteger n)
        {
            if (n == 0) return 0;
            if (n > 0)
            {
                int bitLength = Convert.ToInt32(Math.Ceiling(BigInteger.Log(n, 2)));
                BigInteger root = BigInteger.One << (bitLength / 2);

                while (!isSqrt(n, root))
                {
                    root += n / root;
                    root /= 2;
                }

                return root;
            }

            throw new ArithmeticException("NaN");
        }

        private static Boolean isSqrt(BigInteger n, BigInteger root)
        {
            BigInteger lowerBound = root * root;
            BigInteger upperBound = (root + 1) * (root + 1);

            return (n >= lowerBound && n < upperBound);
        }

        public static bool isPrime(BigInteger n)
        {
            bool res = false;
            for (BigInteger i = 2; i <= Sqrt(n); i++)
            {
                res |= n % i == 0;
                if (res) return !res;
            }
            return !res;
        }

        public static string arrayToString<T>(params T[] arr)
        {
            if (arr.Length == 0) return "";
            string res = arr[0].ToString();
            for (int i = 1; i < arr.Length; i++)
            {
                res += "\n" + arr[i].ToString();
            }
            return res;
        }
    }
}
