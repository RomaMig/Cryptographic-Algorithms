using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Cryptographic_Algorithms
{
    static class Chauma
    {
        public const int BLOCK = 2; //длинна блока по умолчанию
        public const int CODESIZE = 16; //размер кодировки по умолчанию

        public struct Key
        {
            public BigInteger k { get; }
            public BigInteger rk { get; }

            public Key(BigInteger k, BigInteger rk)
            {
                this.k = k;
                this.rk = rk;
            }
        }

        /**
         * Интерфейсы взаимодействия с классом по умолчанию
         */
        public static BigInteger Hash(string msg, RSA.Key oKey)
        {
            return Hash(msg, oKey, BLOCK, CODESIZE);
        }

        public static BigInteger[] encrypt(string msg, RSA.Key oKey)
        {
            return encrypt(msg, oKey, BLOCK, CODESIZE);
        }

        /**
         * Функция генерирования ключей
         * p и q большие простые числа
         */
        public static void getKeys(BigInteger p, BigInteger q, out RSA.Key oKey, out RSA.Key cKey, out Key ck)
        {
            RSA.getKeys(p, q, out oKey, out cKey);
            BigInteger k = Utility.getRandomKey(oKey.N);
            BigInteger rk = Algorithms.gcdex(k, oKey.N);
            ck = new Key(k, rk);
        }

        /**
         * Функция хеширования сообщения
         */
        public static BigInteger Hash(string msg, RSA.Key oKey, int block, int codesize)
        {
            return RSA.Hash(msg, oKey, block, codesize);
        }

        public static BigInteger getMaskedMessage(string msg, RSA.Key oKey, Chauma.Key k, int block, int codesize)
        {
            return Hash(msg, oKey, block, codesize) * Algorithms.pow_mod(k.k, oKey.key, oKey.N) % oKey.N;
        }

        public static BigInteger getSignedMaskedMessage(BigInteger maskedMsg, RSA.Key cKey)
        {
            return Algorithms.pow_mod(maskedMsg, cKey.key, cKey.N);
        }

        public static BigInteger getSignedMessage(BigInteger signedMaskedMsg, RSA.Key oKey, Chauma.Key k)
        {
            return signedMaskedMsg * k.rk % oKey.N;
        }

        /**
         * Шифрование
         */
        public static BigInteger[] encrypt(string msg, RSA.Key oKey, int block, int codesize)
        {
            return RSA.encrypt(msg, oKey, block, codesize);
        }
    }
}
