using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Cryptographic_Algorithms
{
    static class DiffieHellman
    {
        /**
         * Описание секретного ключа, с помощь которого создаются сообщения для получения общего закрытого ключа
         */
        public struct Key
        {
            public BigInteger p { get; }
            public BigInteger alpha { get; }
            public BigInteger key { get; }
            public BigInteger a { get; }

            public Key(BigInteger p, BigInteger alpha, BigInteger key, BigInteger a)
            {
                this.p = p;
                this.alpha = alpha;
                this.key = key;
                this.a = a;
            }
        }

        /**
         * Функция получения ключа для схемы Диффи-Хеллмана
         */
        public static void getKey(BigInteger p, BigInteger alpha, out Key k)
        {
            //генерация случайных чисел
            BigInteger key = Utility.RandomIntegerBelow(p - 2) + 1;
            BigInteger a = Utility.RandomIntegerBelow(p - 2) + 1;

            k = new Key(p, alpha, key, a);
        }

        /**
         * Функция генерации сообщения по схеме Диффи-Хеллмана
         */
        public static BigInteger DiffieHellmanMES(Key k)
        {
            return Algorithms.pow_mod(k.alpha, k.key, k.p); //возвращение сообщения по схеме Диффи-Хеллмана
        }

        /**
         * Функция получения общего закрытого ключа по схеме Диффи-Хеллмана
         */
        public static BigInteger DiffieHellmanCommonKey(BigInteger mes, Key k)
        {
            return Algorithms.pow_mod(mes, k.key, k.p); //возвращение общего закрытого ключа
        }

        /**
         * Функция генерации сообщения по схеме Диффи-Хеллмана с протоколом MTI
         */
        public static void MTIMES(Key k, out BigInteger mes1, out BigInteger mes2)
        {
            mes1 = DiffieHellmanMES(k); //генерация сообщения по схеме Диффи-Хеллмана
            mes2 = Algorithms.pow_mod(k.alpha, k.a, k.p);   //генерация сообщения по протоколу MTI
        }

        /**
         * Функция получения общего закрытого ключа по схеме Диффи-Хеллмана с протоколом MTI
         */
        public static BigInteger MTICommonKey(BigInteger mes1, BigInteger mes2, Key k)
        {
            return (Algorithms.pow_mod(mes1, k.a, k.p) * Algorithms.pow_mod(mes2, k.key, k.p)) % k.p;  //возвращение общего закрытого ключа
        }
    }
}
