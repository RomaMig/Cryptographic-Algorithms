using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Cryptographic_Algorithms
{
    static class RSA
    {
        public const int BLOCK = 2; //длинна блока по умолчанию
        public const int CODESIZE = 16; //размер кодировки по умолчанию

        /**
         * Структура, описывающая открытый и закрытый ключи
         */
        public struct Key
        {
            public BigInteger key { get; }  //значение ключа
            public BigInteger N { get; } //коэффичиент N

            public Key(BigInteger key, BigInteger N)
            {
                this.key = key;
                this.N = N;
            }

            public override string ToString()
            {
                return string.Format("key:{0} N:{1}", key, N);
            }
        }

        /**
         * Интерфейсы взаимодействия с классом по умолчанию
         */
        public static BigInteger Hash(string msg, Key oKey)
        {
            return Hash(msg, oKey, BLOCK, CODESIZE);
        }

        public static BigInteger getEDS(string msg, Key oKey, Key cKey)
        {
            return getEDS(msg, oKey, cKey, BLOCK, CODESIZE);
        }
        
        public static bool EDSVerification(string msg, BigInteger sign, Key oKey)
        {
            return EDSVerification(msg, sign, oKey, BLOCK, CODESIZE);
        }

        public static BigInteger[] encrypt(string msg, Key oKey)
        {
            return encrypt(msg, oKey, BLOCK, CODESIZE);
        }

        public static string decrypt(BigInteger[] code, Key cKey)
        {
            return decrypt(code, cKey, CODESIZE);
        }

        /**
         * Функция генерирования ключей
         * p и q большие простые числа
         */
        public static void getKeys(BigInteger p, BigInteger q, out Key oKey, out Key cKey)
        {
            BigInteger n = p * q; //получаем N
            BigInteger phi = (p - 1) * (q - 1); // получаем ф(N)
            BigInteger ok = Utility.getRandomKey(phi); //выбираем случайный открытый ключ
            BigInteger ck = Algorithms.gcdex(ok, phi); //находим закрытый ключ, как обратный элемент к открытому по модулю ф(N)

            //возвращаем ключи
            oKey = new Key(ok, n);
            cKey = new Key(ck, n);
        }

        /**
         * Функция хеширования сообщения
         */
        public static BigInteger Hash(string msg, Key oKey, int block, int codesize)
        {
            BigInteger[] code = encrypt(msg, oKey, block, codesize); //шифруем сообщение открытым ключом
            BigInteger m = 0; //результат хеш-функции
            for (int i = 0; i < code.Length; i++)
            {
                m ^= code[i];   //складываем по модулю 2
                m %= oKey.N;    //остаток од деления на N
            }
            return m;
        }

        /**
         * Функция получения подписи
         */
        public static BigInteger getEDS(string msg, Key oKey, Key cKey, int block, int codesize)
        {
            return Algorithms.pow_mod(Hash(msg, oKey, block, codesize), cKey.key, oKey.N);
        }

        /**
         * Функция проверки подписи
         */
        public static bool EDSVerification(string msg, BigInteger sign, Key oKey, int block, int codesize)
        {
            return Hash(msg, oKey, block, codesize) == Algorithms.pow_mod(sign, oKey.key, oKey.N);
        }

        /**
         * Шифрование
         */
        public static BigInteger[] encrypt(string msg, Key oKey, int block, int codesize)
        {
            BigInteger[] text = Utility.msgToBlock(msg, block, codesize);  // сжатие и кодировка
            BigInteger[] code = new BigInteger[text.Length];    //объявление массива зашифрованных блоков сообщений

            for (int i = 0; i < text.Length; i++)
            {
                code[i] = Algorithms.pow_mod(text[i], oKey.key, oKey.N);    //шифрование
            }
            return code;
        }

        /**
         * Дешифрование
         */
        public static string decrypt(BigInteger[] code, Key cKey, int codesize)
        {
            BigInteger[] text = new BigInteger[code.Length];    
            for (int i = 0; i < code.Length; i++)
            {
                text[i] = Algorithms.pow_mod(code[i], cKey.key, cKey.N); //дешифрование
            }
            return Utility.blockToMsg(text, codesize);  //объединяем блоки в сообщение
        }
    }
}
