using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Cryptographic_Algorithms
{
    public static class ElGamal
    {
        public const int BLOCK = 2; //длинна блока по умолчанию
        public const int CODESIZE = 16; //размер кодировки по умолчанию

        /**
         * Описание открытого ключа
         */
        public struct OKey
        {
            public BigInteger p { get; }
            public BigInteger g { get; }
            public BigInteger y { get; }

            public OKey(BigInteger p, BigInteger g, BigInteger y)
            {
                this.p = p;
                this.g = g;
                this.y = y;
            }

            public override string ToString()
            {
                return string.Format("P:{0} G:{1} Y:{2}", p, g, y);
            }
        }

        /**
         * Описание закрытого ключа
         */
        public struct CKey
        {
            public BigInteger p { get; }
            public BigInteger x { get; }

            public CKey(BigInteger p, BigInteger x)
            {
                this.p = p;
                this.x = x;
            }
        }

        /**
         * Описание криптограммы
         */
        public struct Cryptogramm
        {
            public BigInteger a { get; }
            public BigInteger[] b { get; }

            public Cryptogramm(BigInteger a, BigInteger[] b)
            {
                this.a = a;
                this.b = b;
            }
        }

        /**
         * Описание подписи
         */
        public struct Sign
        {
            public BigInteger a;
            public BigInteger b;

            public Sign(BigInteger a, BigInteger b)
            {
                this.a = a;
                this.b = b;
            }

            public override string ToString()
            {
                return string.Format("a:{0} b:{1}", a, b);
            }
        }

        /**
         * Интерфейсы взаимодействия с классом по умолчанию
         */
        public static BigInteger Hash(string msg, OKey oKey)
        {
            return Hash(msg, oKey, BLOCK, CODESIZE);
        }

        public static Sign getEDS(string msg, OKey oKey, CKey cKey)
        {
            return getEDS(msg, oKey, cKey, BLOCK, CODESIZE);
        }

        public static bool EDSVerification(string msg, Sign sign, OKey oKey)
        {
            return EDSVerification(msg, sign, oKey, BLOCK, CODESIZE);
        }

        public static Cryptogramm encrypt(string msg, OKey oKey)
        {
            return encrypt(msg, oKey, BLOCK, CODESIZE);
        }

        public static string decrypt(Cryptogramm code, CKey cKey)
        {
            return decrypt(code, cKey, CODESIZE);
        }

        /**
         * Функция генерирования ключей
         * p большое простое число
         */
        public static void getKeys(BigInteger p, out OKey oKey, out CKey cKey)
        {
            BigInteger g = Utility.RandomIntegerBelow(p);   //случайный G меньший p
            BigInteger x = Utility.RandomIntegerBelow(p);   //случайный X меньший p (закрытый)
            BigInteger y = Algorithms.pow_mod(g, x, p);     //получение открытого ключа

            //создание открытого и закрытого ключей
            oKey = new OKey(p, g, y);   
            cKey = new CKey(p, x);
        }

        /**
         * Функция хеширования сообщения
         */
        public static BigInteger Hash(string msg, OKey oKey, int block, int codesize)
        {
            BigInteger m = 0; //результат хеш-функции
            BigInteger[] text = Utility.msgToBlock(msg, block, codesize);   //разбиваем сообщение на блоки

            //поблочно хешируем, получая хеш сообщения
            for (int i = 0; i < text.Length; i++)
            {
                m ^= Algorithms.pow_mod(text[i], oKey.y, oKey.p);
                m %= oKey.p;
            }
            return m;
        }

        /**
         * Функция получения подписи
         */
        public static Sign getEDS(string msg, OKey oKey, CKey cKey, int block, int codesize)
        {
            BigInteger k = Utility.getRandomKey(oKey.p - 1);    //получаем случайное число K
            BigInteger kr = Algorithms.gcdex(k, oKey.p - 1);    //обратный элемент к К
            BigInteger a = Algorithms.pow_mod(oKey.g, k, oKey.p);   //вычисляем а и b
            BigInteger b = (kr * (Hash(msg, oKey, block, codesize) - a * cKey.x)) % (oKey.p - 1);   
            if (b < 0) b += oKey.p - 1; //нормирование по модулю

            return new Sign(a, b);
        }

        /**
         * Функция проверки подписи
         */
        public static bool EDSVerification(string msg, Sign sign, OKey oKey, int block, int codesize)
        {
            return Algorithms.pow_mod(oKey.g, Hash(msg, oKey, block, codesize), oKey.p) == Algorithms.pow_mod(oKey.y, sign.a, oKey.p) * Algorithms.pow_mod(sign.a, sign.b, oKey.p) % oKey.p;
        }

        /**
         * Шифрование
         */
        public static Cryptogramm encrypt(string msg, OKey oKey, int block, int codesize)
        {
            BigInteger[] text = Utility.msgToBlock(msg, block, codesize);   //разбиваем сообщеине на блоки
            BigInteger k = Utility.getRandomKey(oKey.p - 1);    //получаем случайное число К
            BigInteger a = Algorithms.pow_mod(oKey.g, k, oKey.p);   //первая часть шифротекста
            BigInteger[] b = new BigInteger[text.Length];
            BigInteger ykmodp = Algorithms.pow_mod(oKey.y, k, oKey.p); //заранее вычисляем Y^k mod p
            for (int i = 0; i < b.Length; i++)
            {
                b[i] = ykmodp * text[i] % oKey.p;  //вычисляем шифротекст
            }
            return new Cryptogramm(a, b);   //возвращаем криптограмму
        }

        /**
         * Дешифрование
         */
        public static string decrypt(Cryptogramm code, CKey cKey, int codesize)
        {
            BigInteger ax = Algorithms.pow_mod(code.a, cKey.x, cKey.p); //вычисляем а^x
            BigInteger arx = Algorithms.gcdex(ax, cKey.p);  //находим для a^x обратный элемент
            BigInteger[] text = new BigInteger[code.b.Length];
            for (int i = 0; i < text.Length; i++)
            {
                text[i] = code.b[i] * arx % cKey.p; //дешифруем блоки сообщения
            }
            return Utility.blockToMsg(text, codesize);  //объединяем блоки в сообщение
        }
    }
}
