namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////
    // Интерфейс аддитивной группы
    ////////////////////////////////////////////////////////////////////////////
    public interface IGroupAdd<E> 
    {
        // признак нулевого элемента
        bool IsZero(E a); E Zero { get; } 
    
        // противоположный и удвоенный элемент
        E Negate(E a); E Twice(E a);
    
        // сложение и вычитание элементов
        E Add(E a, E b); E Subtract(E a, E b);
    
        // вычисление кратного элемента
        E Multiply(E a, BigInteger e); 
        
        // сумма кратных элементов
        E MultiplySum(E P, BigInteger a, E Q, BigInteger b); 
    }
}
