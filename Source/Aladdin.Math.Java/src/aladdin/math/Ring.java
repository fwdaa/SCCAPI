package aladdin.math;
import java.lang.reflect.*;
import java.math.*;

////////////////////////////////////////////////////////////////////////////
// Интерфейс кольца
////////////////////////////////////////////////////////////////////////////
public abstract class Ring<E> extends GroupAdd<E> implements IRing<E>
{
    private static final long serialVersionUID = 7144127971844674154L;
    
    // нулевой элемент
    @Override public abstract E zero(); 
    // противоположный элемент
    @Override public abstract E negate(E a);
    // сложение элементов
    @Override public abstract E add(E a, E b); 
    
    // признак единичного элемента
    @Override public boolean isOne(E a) { return a.equals(one()); }
    // единичный элемент
    @Override public abstract E one();
    
    // умножение элементов
    @Override public abstract E product  (E a, E b); 
    
    // вычисление частного и остатка
    @Override public abstract E divide   (E a, E b); 
    @Override public abstract E remainder(E a, E b); 

    // вычисление частного и остатка
    @SuppressWarnings({"unchecked"}) 
    @Override public E[] divideAndRemainder(E a, E b)
    {
		// создать результирующий массив
        E[] result = (E[])Array.newInstance(a.getClass(), 2); 
        
        // вычислить частное и остаток
        result[0] = divide(a, b); result[1] = remainder(a, b); return result; 
    }
    // возведение в квадрат
    @Override public E sqr(E a) { return product(a, a); } 
    
    // вычисление степени элемента
    @Override public E power(E a, BigInteger e)
    {
        // проверить необходимость вычислений
        if (isOne(a) || e.signum() == 0) return one(); E r = a; 

        // обработать отрицательную степень
        if (e.signum() < 0) throw new IllegalArgumentException(); 
        
  		// для всех битов
        for (int i = e.bitLength() - 2; i >= 0; i--)
        {
            // выполнить вычисления
            r = sqr(r); if (e.testBit(i)) r = product(r, a);
        }
        return r; 
    }
    // произведение степеней элементов 
    @Override public E power_product(E P, BigInteger a, E Q, BigInteger b)
    {
        // проверить корректность данных
        if (a.signum() < 0 || b.signum() < 0) throw new IllegalArgumentException(); 
        
        // определить разрядность большего сомножителя
		int bits = Math.max(a.bitLength(), b.bitLength());

		// задать начальные условия
		E R = one(); E Z = product(P, Q);

		// для всех битов
		for (int i = bits - 1; i >= 0; i--)
		{
            // извлечь значение битов
            boolean aBit = a.testBit(i); 
            boolean bBit = b.testBit(i); R = sqr(R);
            
            // выполнить вычисления
            if (aBit) R = product(R, bBit ? Z : P); 
            
            // выполнить вычисления
            else if (bBit) R = product(R, Q);
		}
		return R;
    }
    ///////////////////////////////////////////////////////////////////////
    // Наибольший общий делитель
    ///////////////////////////////////////////////////////////////////////
    @Override public final E gcd(E A, E B)
    {
		// обработать нулевые числа
		if (isZero(B)) return A; if (isZero(A)) return B;

        // задать начальные условия для алгоритма
		E divident = A; E divisor = B;

		// выполнить алгоритм Евклида
		while (!isZero(divisor))
		{
            // вычислить остаток от деления
            E remainder = remainder(divident, divisor);

            // переустановить делимое и делитель
            divident = divisor; divisor = remainder;
		}
		// вернуть последний остаток
		return divident;
    }
    ///////////////////////////////////////////////////////////////////////
    // Расширенный алгоритм Евклида
    ///////////////////////////////////////////////////////////////////////
    @SuppressWarnings({"unchecked"}) 
    @Override public final E[] euclid(E A, E B)
    {
		// создать результирующий массив
        E[] result = (E[])Array.newInstance(A.getClass(), 3); 

        // инвариант U1 * A + V1 * B = Ai
		// инвариант U2 * A + V2 * B = Bi
		E Ai = A; E U1 = one (); E V1 = zero();
		E Bi = B; E U2 = zero(); E V2 = one ();

		// выполнять пока делитель больше нуля
		for (E[] Q; !isZero(Bi); Ai = Bi, Bi = Q[1])
		{
            // вычислить частное и остаток от деления
            Q = divideAndRemainder(Ai, Bi);

            // пересчитать коэффициенты инварианта
            E TU = subtract(U1, product(U2, Q[0]));
            E TV = subtract(V1, product(V2, Q[0]));

            // переустановить коэффициенты
            U1 = U2; V1 = V2; U2 = TU; V2 = TV;
        }
        // вернуть результат
        result[0] = Ai; result[1] = U1; result[2] = V1; return result; 
    }  
}