package aladdin.math;
import java.io.*;
import java.math.*; 

////////////////////////////////////////////////////////////////////////////
// Интерфейс группы
////////////////////////////////////////////////////////////////////////////
public interface IGroup<E> extends Serializable
{
    // признак нулевого элемента
    boolean isIdentity(E a); E identity();
    
    // сложение элементов и противоположный элемент
    E operation(E a, E b); E revert(E a);
    
    // вычисление кратного элемента
    E multiply_operation(E a, BigInteger e); 
        
    // сумма кратных элементов
    E multiply_operation(E P, BigInteger a, E Q, BigInteger b); 
}
