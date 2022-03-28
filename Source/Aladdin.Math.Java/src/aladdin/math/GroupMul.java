package aladdin.math;
import java.math.*; 

////////////////////////////////////////////////////////////////////////////
// Мультипликативная группа (умножение скользящим окном)
////////////////////////////////////////////////////////////////////////////
public abstract class GroupMul<E> extends Group<E> implements IGroupMul<E>
{
    private static final long serialVersionUID = 1542785450834169951L;
    
    // признак единичного элемента
    @Override public boolean isOne(E a) { return a.equals(one()); } 
    
    // единичный и обратный элемент
    @Override public abstract E one(); @Override public abstract E invert(E a);
    
    // умножение элементов
    @Override public abstract E product(E a, E b); 
 
    // деление элементов
    @Override public E divide(E a, E b) { return isOne(b) ? a : product(a, invert(b)); }
        
    // возведение в квадрат
    @Override public E sqr(E a) { return product(a, a); }
        
    // возведение в степень 
    @Override public E power(E a, BigInteger e) { return multiply_operation(a, e); }
    
    // произведение степеней элементов 
    @Override public E power_product(E P, BigInteger a, E Q, BigInteger b)
    {
        // сумма кратных элементов
        return multiply_operation(P, a, Q, b); 
    }
    // признак нулевого элемента
    @Override public final boolean isIdentity(E a) { return isOne(a); } 

    // нулевой элемент
    @Override public final E identity() { return one(); } 
        
    // противоположный элемент
    @Override public final E revert(E a) { return invert(a); } 
        
    // сложение элементов
    @Override public final E operation(E a, E b) { return product(a, b); } 

    // возведение в степень 
    @Override public final E multiply_operation(E a, BigInteger e) 
    { 
        // проверить необходимость вычислений
        if (isIdentity(a) || e.signum() == 0) return identity(); 

        // обработать отрицательный сомножитель
        if (e.signum() < 0) return revert(multiply_operation(a, e.abs())); E r = a; 
        
        // для всех битов
        for (int i = e.bitLength() - 2; i >= 0; i--)
        {
            // выполнить вычисления
            r = operation(r, r); if (e.testBit(i)) r = operation(r, a);
        }
        return r;
    }
}
