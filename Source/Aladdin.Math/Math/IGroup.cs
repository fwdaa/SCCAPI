namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////
    // Интерфейс группы
    ////////////////////////////////////////////////////////////////////////////
    public interface IGroup<E> 
    {
        // признак нулевого элемента
        bool IsIdentity(E a); E Identity { get; }
    
        // сложение элементов и противоположный элемент
        E Operation(E a, E b); E Revert(E a);
    
        // вычисление кратного элемента
        E MultiplyOperation(E a, BigInteger e); 
        
        // сумма кратных элементов
        E MultiplyOperation(E P, BigInteger a, E Q, BigInteger b); 
    }
}
