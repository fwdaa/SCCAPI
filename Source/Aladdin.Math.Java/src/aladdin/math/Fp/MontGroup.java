package aladdin.math.Fp;
import aladdin.math.GroupMul;
import aladdin.math.Utils;
import java.math.*; 

////////////////////////////////////////////////////////////////////////////////
// Группа Монтгомери
////////////////////////////////////////////////////////////////////////////////
public class MontGroup extends GroupMul<BigInteger>
{
    private static final long serialVersionUID = 4859957514212254420L;
    
    // значение и закодированное представление модуля
    private final BigInteger P; private final int[] arrP; 
    
    // число битов и обратный элемент для младшего слова
    private final int bitsP; private final long p0; 
    
    // конструктор
    public MontGroup(BigInteger P) 
    { 
    	// проверить корректность операнда
        if (P.signum() <= 0) throw new IllegalArgumentException();
        
        // сохранить переданные параметры
        this.P = P; this.bitsP = P.bitLength();
        
        // получить представления модуля
        arrP = Utils.bitsToUints(P.toByteArray(), bitsP); 
        
        // извлечь младшие разряды
        long word32 = lo32(arrP[arrP.length - 1]); 
        
        // проверить корректность значения
        long inverse = word32; if ((inverse & 1) == 0)
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // вычислить обратный элемент по модулю 2^32
        inverse = lo32(inverse + inverse - inverse * inverse * word32);
        inverse = lo32(inverse + inverse - inverse * inverse * word32);
        inverse = lo32(inverse + inverse - inverse * inverse * word32);
        inverse = lo32(inverse + inverse - inverse * inverse * word32);

        // вычислить обратный элемент
        this.p0 = lo32(0 - inverse); 
    } 
    // вернуть модуль поля
    public final BigInteger p() { return P; }

    // единица Монтгомери
    @Override public BigInteger one() 
    {
		// вернуть единицу Монтгомери
		return BigInteger.ONE.shiftLeft((bitsP + 31) / 32 * 32).mod(P);
    }
    // умножение по Монтгомери
    @Override public BigInteger product(BigInteger A, BigInteger B) 
    {
        // проверить на нулевое значение
		if (A.signum() == 0 || B.signum() == 0) return BigInteger.ZERO;
        
        // получить представления чисел
        byte[] encodedA = A.toByteArray(); byte[] encodedB = B.toByteArray();
        
        // создать вспомогательные массив
        int[] arrC = new int[arrP.length + 1]; 
        
        // получить представления чисел
        int[] arrA = Utils.bitsToUints(encodedA, bitsP);
        int[] arrB = Utils.bitsToUints(encodedB, bitsP);

        // для всех разрядов
        for (int i = arrP.length - 1; i >= 0; i--)
        {
            // вычислить mult = ((C[0] + A[i] * B[0]) * p0) mod 2^32
            long mult = lo32(lo32(arrC[arrP.length] + lo32(arrA[i]) * lo32(arrB[arrP.length - 1])) * p0);

            //////////////////////////////////////////////////
            // вычислить C = (C + A[i] * B + mult * P) / 2^32
            //////////////////////////////////////////////////

            // вычислить A[i] * B[0] и mult * P[0]
            long prod1 = lo32(arrA[i]) * lo32(arrB[arrP.length - 1]);
            long prod2 =       mult    * lo32(arrP[arrP.length - 1]);

            // выделить младшие и страшие разряды произведений
            long loProd1 = lo32(prod1); long hiProd1 = hi32(prod1);
            long loProd2 = lo32(prod2); long hiProd2 = hi32(prod2); 

            // вычислить C[0] + A[i] * B[0] + mult * P[0]
            long loSum = lo32(arrC[arrP.length]) + loProd1 + loProd2;
            long hiSum = hi32(loSum            ) + hiProd1 + hiProd2;

            // проверить логическое условие
            if (lo32(loSum) != 0) throw new ArithmeticException();  

            // для всех последующих разрядов
            for (int j = arrP.length - 1; j > 0; j--)
            {
                // вычислить A[i] * B[j] и mult * P[j]
                prod1 = lo32(arrA[i]) * lo32(arrB[j - 1]);
                prod2 =       mult    * lo32(arrP[j - 1]);

                // выделить младшие и страшие разряды произведений
                loProd1 = lo32(prod1); hiProd1 = hi32(prod1);
                loProd2 = lo32(prod2); hiProd2 = hi32(prod2);

                // вычислить C[j] + A[i] * B[j] + mult * P[j]
                loSum = lo32(hiSum) + lo32(arrC[j]) + loProd1 + loProd2;
                hiSum = hi32(hiSum) + hi32(loSum  ) + hiProd1 + hiProd2;

                // установить вычисленный разряд
                arrC[j + 1] = (int)lo32(loSum); 
            }
            // добавить C[n+1] c учетом возможных переносов
            loSum = lo32(hiSum) + lo32(arrC[0]);
            hiSum = hi32(hiSum) + hi32(loSum  );

            // проверить логическое условие
            if (hi32(hiSum) != 0) throw new ArithmeticException(); 

            // установить вычисленные разряды
            arrC[1] = (int)lo32(loSum); arrC[0] = (int)lo32(hiSum);
        }
        // создать большое число по представлению
        BigInteger C = new BigInteger(1, Utils.uintsToBits(arrC, bitsP + 1));
        
        // при необходимости вычесть модуль
        return (C.compareTo(P) >= 0) ? C.subtract(P) : C; 
    }
    // умножение на обратный элемент
    @Override public BigInteger divide(BigInteger a, BigInteger b) 
    { 
        // умножение на обратный элемент
        return product(a, invert(b)); 
    }
    // вычисление обратного элемента
    @Override public BigInteger invert(BigInteger a) 
    {
        // метод не реализован
        throw new UnsupportedOperationException(); 
    }
    // выделение старших и младших разрядов
    private static long lo32(long A) { return A & 0xFFFFFFFFL; }
    private static long hi32(long A) { return A >>> 32;        }
}
