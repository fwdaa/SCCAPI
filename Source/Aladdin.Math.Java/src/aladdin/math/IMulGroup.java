package aladdin.math;
import java.math.*;

////////////////////////////////////////////////////////////////////////////
// Интерфейс мультипливативной группы
////////////////////////////////////////////////////////////////////////////
public interface IMulGroup<E> 
{
    // признак единичного элемента
    boolean isOne(E a); E one();
    
    // обратный и возведенный в квадрат элемент
    E invert(E a); E sqr(E a);
    
    // умножение и деление элементов
    E product(E a, E b); E divide(E a, E b);
    
    // возведение в степень элемента
    E power(E a, BigInteger e); 
        
    // произведение возведенных в степень элементов
    E power_product(E P, BigInteger a, E Q, BigInteger b); 
}
