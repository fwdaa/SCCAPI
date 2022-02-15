package aladdin.math;
import java.math.*;

////////////////////////////////////////////////////////////////////////////
// Интерфейс аддитивной группы
////////////////////////////////////////////////////////////////////////////
public interface IAddGroup<E> 
{
    // признак нулевого элемента
    boolean isZero(E a); E zero();
    
    // противоположный и удвоенный элемент
    E negate(E a); E twice(E a);
    
    // сложение и вычитание элементов
    E add(E a, E b); E subtract(E a, E b);
    
    // вычисление кратного элемента
    E multiply(E a, BigInteger e); 
        
    // сумма кратных элементов
    E multiply_sum(E P, BigInteger a, E Q, BigInteger b); 
}
