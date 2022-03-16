using System; 

namespace Aladdin.Math.Fp
{
    ////////////////////////////////////////////////////////////////////////////////
    // Группа Монтгомери
    ////////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class MontGroup : GroupMul<BigInteger>
    {
        // значение и закодированное представление модуля
        private BigInteger p; private UInt32[] arrP; 
    
        // число битов и обратный элемент для младшего слова
        private int bitsP; private UInt32 p0; 
    
        // конструктор
        public MontGroup(BigInteger p) 
        { 
    	    // проверить корректность операнда
            if (p.Signum <= 0) throw new ArgumentException();
        
            // сохранить переданные параметры
            this.p = p; this.bitsP = p.BitLength;
        
            // получить представления модуля
            arrP = Utils.BitsToUints(p.ToByteArray(), bitsP); 
        
            // извлечь младшие разряды
            UInt32 word32 = arrP[arrP.Length - 1]; 
        
            // проверить корректность значения
            UInt32 inverse = word32; if ((inverse & 1) == 0)
            {
                // при ошибке выбросить исключение
                throw new ArgumentException(); 
            }
            // вычислить обратный элемент по модулю 2^32
            inverse = inverse + inverse - inverse * inverse * word32;
            inverse = inverse + inverse - inverse * inverse * word32;
            inverse = inverse + inverse - inverse * inverse * word32;
            inverse = inverse + inverse - inverse * inverse * word32;

            // вычислить обратный элемент
            this.p0 = 0 - inverse; 
        } 
        // вернуть модуль поля
        public BigInteger P { get { return p; }}

        // единица Монтгомери
        public override BigInteger One { get 
        {
		    // вернуть единицу Монтгомери
		    return BigInteger.One.ShiftLeft((bitsP + 31) / 32 * 32).Mod(P);
        }}
        // умножение по Монтгомери
        public override BigInteger Product(BigInteger A, BigInteger B) 
        {
            // проверить на нулевое значение
		    if (A.Signum == 0 || B.Signum == 0) return BigInteger.Zero;
        
            // получить представления чисел
            byte[] encodedA = A.ToByteArray(); byte[] encodedB = B.ToByteArray();
        
            // создать вспомогательные массив
            UInt32[] arrC = new UInt32[arrP.Length + 1]; 

            // получить представления чисел
            UInt32[] arrA = Utils.BitsToUints(encodedA, bitsP);
            UInt32[] arrB = Utils.BitsToUints(encodedB, bitsP);

            // для всех разрядов
            for (int i = arrP.Length - 1; i >= 0; i--)
            {
                // вычислить mult = ((C[0] + A[i] * B[0]) * p0) mod 2^32
                UInt32 mult = (arrC[arrP.Length] + arrA[i] * arrB[arrP.Length - 1]) * p0;

                //////////////////////////////////////////////////
                // вычислить C = (C + A[i] * B + mult * P) / 2^32
                //////////////////////////////////////////////////

                // вычислить A[i] * B[0] и mult * P[0]
                UInt64 prod1 = (UInt64)arrA[i] * arrB[arrP.Length - 1];
                UInt64 prod2 = (UInt64)mult    * arrP[arrP.Length - 1];

                // выделить младшие и страшие разряды произведений
                UInt32 loProd1 = lo32(prod1); UInt32 hiProd1 = hi32(prod1);
                UInt32 loProd2 = lo32(prod2); UInt32 hiProd2 = hi32(prod2); 

                // вычислить C[0] + A[i] * B[0] + mult * P[0]
                UInt64 loSum = (UInt64)arrC[arrP.Length] + loProd1 + loProd2;
                UInt64 hiSum = (UInt64)hi32(loSum      ) + hiProd1 + hiProd2;

                // проверить логическое условие
                if (lo32(loSum) != 0) throw new ArithmeticException();  

                // для всех последующих разрядов
                for (int j = arrP.Length - 1; j > 0; j--)
                {
                    // вычислить A[i] * B[j] и mult * P[j]
                    prod1 = (UInt64)(arrA[i]) * arrB[j - 1];
                    prod2 = (UInt64)   mult   * arrP[j - 1];

                    // выделить младшие и страшие разряды произведений
                    loProd1 = lo32(prod1); hiProd1 = hi32(prod1);
                    loProd2 = lo32(prod2); hiProd2 = hi32(prod2);

                    // вычислить C[j] + A[i] * B[j] + mult * P[j]
                    loSum = (UInt64)lo32(hiSum) + arrC[j]     + loProd1 + loProd2;
                    hiSum = (UInt64)hi32(hiSum) + hi32(loSum) + hiProd1 + hiProd2;

                    // установить вычисленный разряд
                    arrC[j + 1] = (UInt32)(loSum); 
                }
                // добавить C[n+1] c учетом возможных переносов
                loSum = (UInt64)lo32(hiSum) + arrC[0];
                hiSum = (UInt64)hi32(hiSum) + hi32(loSum);

                // проверить логическое условие
                if (hi32(hiSum) != 0) throw new ArithmeticException(); 

                // установить вычисленные разряды
                arrC[1] = (UInt32)(loSum); arrC[0] = (UInt32)(hiSum);
            }
            // создать большое число по представлению
            BigInteger C = new BigInteger(1, Utils.UintsToBits(arrC, bitsP + 1));
        
            // при необходимости вычесть модуль
            return (C.CompareTo(P) >= 0) ? C.Subtract(P) : C; 
        }
        // умножение на обратный элемент
        public override BigInteger Divide(BigInteger a, BigInteger b) 
        { 
            // умножение на обратный элемент
            return Product(a, Invert(b)); 
        }
        // вычисление обратного элемента
        public override BigInteger Invert(BigInteger a) 
        {
            // метод не реализован
            throw new NotSupportedException(); 
        }
        // выделение старших и младших разрядов
        private static UInt32 lo32(UInt64 A) { return (UInt32)(A & 0xFFFFFFFF); }
        private static UInt32 hi32(UInt64 A) { return (UInt32)(A >> 32       ); }
    }
}
