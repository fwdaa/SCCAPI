package aladdin.math;
import java.lang.reflect.*;
import java.math.*;

////////////////////////////////////////////////////////////////////////////
// Интерфейс поля
////////////////////////////////////////////////////////////////////////////
public abstract class Field<E> extends Ring<E> implements IField<E>
{
    ///////////////////////////////////////////////////////////////////////
    // Кодирование элементов
    ///////////////////////////////////////////////////////////////////////
    
    // преобразовать в число
    // public abstract BigInteger toBigInteger(E element); 
    // преобразовать из числа
    // public abstract E fromBigInteger(BigInteger element) throws IOException; 
    
    ///////////////////////////////////////////////////////////////////////
    // Операции поля
    ///////////////////////////////////////////////////////////////////////
    
    // вычислить обратный элемент
    @Override public abstract E invert(E a);
              
    // умножить на обратный элемент
    @Override public E divide(E a, E b)  
    {
        // умножить на обратный элемент
        return (isOne(b)) ? a : product(a, invert(b)); 
    }
    // вычисление степени элемента 
    @Override public E power(E a, BigInteger e)
    {
        // обработать отрицательный сомножитель
        if (e.signum() < 0) return invert(power(a, e.abs())); 
        
        // вызвать базовую функцию
        return super.power(a, e); 
    }
    // произведение степеней элементов 
    @Override public E power_product(E P, BigInteger a, E Q, BigInteger b)
    {
        // проверить корректность данных
        if (a.signum() < 0) { P = invert(P); a = a.abs(); }
        if (b.signum() < 0) { Q = invert(Q); b = b.abs(); }
        
        // вызвать базовую функцию
        return super.power_product(P, a, Q, b); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Операции кольца
    ///////////////////////////////////////////////////////////////////////
    @Override public final E remainder (E a, E b) { return zero(); } 
    
    // вычисление частного и остатка
    @SuppressWarnings({"unchecked"}) 
    @Override public final E[] divideAndRemainder(E a, E b)
    {
		// создать результирующий массив
        E[] result = (E[])Array.newInstance(a.getClass(), 2); 

        // вычисление частного и остатка
        result[0] = divide(a, b); result[1] = zero(); return result; 
    }
}