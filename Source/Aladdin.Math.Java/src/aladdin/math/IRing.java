package aladdin.math;
import java.math.*;

////////////////////////////////////////////////////////////////////////////
// Интерфейс кольца
////////////////////////////////////////////////////////////////////////////
public interface IRing<E> extends IGroupAdd<E>
{
    // признак единичного элемента
    boolean isOne(E a); E one();
    
    // умножение/возведение в квадрат
    E product(E a, E b); E sqr(E a); 
    
    // вычисление частного и остатка
    E divide(E a, E b); E remainder(E a, E b);
    
    // вычисление частного и остатка
    E[] divideAndRemainder(E a, E b);

    // вычисление степени элемента
    E power(E a, BigInteger e); 
    
    // произведение степеней элементов 
    E power_product(E P, BigInteger a, E Q, BigInteger b); 
    
    // расширенный алгоритм Евклида
    E[] euclid(E A, E B); E gcd(E A, E B);
}
