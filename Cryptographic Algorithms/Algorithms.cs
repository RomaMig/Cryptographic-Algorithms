using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Cryptographic_Algorithms
{
    static class Algorithms
    {
        /**
         * 1 лаба
         * Функция возведения в степень по модулю по схеме Горнера, ограниченная одним машинным словом
         * a-основание, x-степень, m-модуль
         * возвращает a^x mod m
         */
        public static BigInteger pow_mod32(BigInteger a, BigInteger x, BigInteger m)
        {
            if (m == 0) return -1;  //если модуль равень 0, то делим на ноль, ошибка-выход
            if (x == 0) return 1;   //если степень 0, то результат 1
            if (a == 0 || a == 1) return a;   //если основание рано 0 или 1, то возвращаем основание
            int k;      //объявление переменную k, хранит степень в которую мы возводим 2
            BigInteger r, y;    //объявление переменных r и y
            for (k = 0, r = 1; k <= 32 && r <= x; k++, r <<= 1) ;   //пока мы не выйдем за границы машинного слова и два в степени k <= x;
            if (k == 0 || k > 32) return -1;    //если что-то пошло не так, ошибка-выход
            r = a;  
            y = x % 2 == 0 ? 1 : a;     //если х четное то 1, иначе a
            for (int i = 1; i < k; i++)  //пока не дойдем до k
            {
                r = r * r % m;  //r хранит результат возведения предыдущего значения в квадрат по модулю m
                x >>= 1;    //сдвигаемся на следующий бит
                if (x % 2 == 1)  //берем старший бит, если он равен 1, то 
                    y = y * r % m;  //записываем по битам степени
            }
            return y;  //возвращаем результат
        }

        /**
         * 2 лаба
         * Функция получения обратного элемента по модулю(Расширенный алгоритм Евклида)
         * a-элемент, для которого ищется обратный, n-модуль
         * возвращает a^-1 : a^-1 * a mod n = 1
         */
        public static BigInteger gcdex(BigInteger a, BigInteger n) 
        {
            if (a == 0 || n <= 1)  //если данные неверные, выход-ошибка 
                return -1;

            BigInteger q;
            BigInteger[] u = new BigInteger[3] { 0, 1, n };  //создаем вектор U 
            BigInteger[] v = new BigInteger[3] { 1, 0, a };  //создаем вектор V
            BigInteger[] t = new BigInteger[3];   //буфферный массив для свапа значений u и v

            /*
             * в U лежат предыдущие значения, в V текущие
             * на 0 позиции вычисляется x, на 1 - y, на 2 - НОД
             * вектор t используется как буффер
             */
            while (u[2] > 1 && v[2] != 0)
            {
                q = u[2] / v[2];    // целая часть от деления
                for (int i = 0; i < 3; i++)
                {
                    t[i] = u[i] - v[i] * q;  //находим остаток от деления
                    u[i] = v[i];    //свап
                    v[i] = t[i];
                }
            }
            if (u[2] == 1)  //если числа взаимнопростые, то выводим результат, иначе обратного элемента не существует
                return u[0] < 0 ? n + u[0] : u[0];  //нормируем элемент по модулю
            return -1;
        }

        /**
         * Функция возведения в степень по модулю по схеме Горнера без ограничений по памяти
         * a-основание, x-степень, m-модуль
         * возвращает a^x mod m
         */
        public static BigInteger pow_mod(BigInteger a, BigInteger x, BigInteger m)
        {
            if (m == 0) return -1;
            if (x == 0) return 1;
            if (a == 0 || a == 1) return a;
            BigInteger k, r, y;
            for (k = 0, r = 1; r <= x; k++, r <<= 1) ;
            if (k == 0) return -1;
            r = a;
            y = x % 2 == 0 ? 1 : a;
            for (int i = 1; i < k; i++)
            {
                r = r * r % m;
                x /= 2;
                if (x % 2 == 1)
                    y = y * r % m;
            }
            return y;
        }

        /**
         * Функция возведения в степень по Схеме Горнера без ограничений по памяти
         * a-основание, x-степень
         * возвращает a^x
         */
        public static BigInteger pow(BigInteger a, BigInteger x)
        {
            if (x == 0) return 1;
            if (a == 0 || a == 1) return a;
            int k;
            BigInteger r, y;
            for (k = 0, r = 1; r <= x; k++, r <<= 1) ;
            if (k == 0) return -1;
            r = a;
            y = x % 2 == 0 ? 1 : a;
            for (int i = 1; i < k; i++)
            {
                r *= r;
                x /= 2;
                if (x % 2 == 1)
                    y *= r;
            }
            return y;
        }
    }
}
