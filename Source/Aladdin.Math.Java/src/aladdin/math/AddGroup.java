package aladdin.math;
import java.math.*; 

////////////////////////////////////////////////////////////////////////////
// Аддитивная группа (умножение NAF)
////////////////////////////////////////////////////////////////////////////
public abstract class AddGroup<E> extends Group<E> implements IAddGroup<E>
{
    // признак нулевого элемента
    @Override public boolean isZero(E a) { return a.equals(zero()); } 
    // нулевой элемент
    @Override public abstract E zero(); 
    
    // противоположный элемент
    @Override public abstract E negate(E a);
    
    // сложение элементов
    @Override public abstract E add(E a, E b); 
    // удвоение элемента
    @Override public E twice(E a) { return add(a, a); }
        
    // вычитание элементов
    @Override public E subtract(E a, E b) { return isZero(b) ? a : add(a, negate(b)); }
        
    // вычисление кратного элемента
    @Override public E multiply(E a, BigInteger e) { return multiply_operation(a, e); }
    
    // сумма кратных элементов
    @Override public E multiply_sum(E P, BigInteger a, E Q, BigInteger b)
    {
        // сумма кратных элементов
        return multiply_operation(P, a, Q, b); 
    }
    // признак нулевого элемента
    @Override public final boolean isIdentity(E a) { return isZero(a); } 

    // нулевой элемент
    @Override public final  E identity() { return zero(); } 
        
    // противоположный элемент
    @Override public final E revert(E a) { return negate(a); } 
        
    // сложение элементов
    @Override public final E operation(E a, E b) { return add(a, b); } 

    // вычисление кратного элемента
    @Override public final E multiply_operation(E a, BigInteger e) 
    { 
        // проверить необходимость вычислений   
        if (isIdentity(a) || e.signum() == 0) return identity(); 

        // обработать отрицательный сомножитель
        if (e.signum() < 0) return revert(multiply_operation(a, e.abs())); E r = a; 
        
        // выполнить умножение на 3
        BigInteger h = e.multiply(BigInteger.valueOf(3)); E n = revert(a);
        
        // для всех битов
        for (int i = h.bitLength() - 2; i > 0; i--)
        {
            // выполнить вычисления
            boolean hBit = h.testBit(i); r = operation(r, r); 

            // выполнить вычисления
            if (hBit != e.testBit(i)) r = operation(r, hBit ? a : n);
        }
        return r;
    } 
}
