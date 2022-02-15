namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////
    // Интерфейс кольца
    ////////////////////////////////////////////////////////////////////////////
    public interface IRing<E> : IGroupAdd<E>
    {
        // признак единичного элемента
        bool IsOne(E a); E One { get; }
    
        // умножение/возведение в квадрат
        E Product(E a, E b); E Sqr(E a); 
    
        // вычисление частного и остатка
        E Divide(E a, E b); E Remainder(E a, E b);
    
        // вычисление частного и остатка
        E[] DivideAndRemainder(E a, E b);

        // вычисление степени элемента
        E Power(E a, BigInteger e); 
    
        // произведение степеней элементов 
        E PowerProduct(E P, BigInteger a, E Q, BigInteger b); 
    
        // расширенный алгоритм Евклида
        E[] Euclid(E A, E B); E GCD(E A, E B);
    }
}
