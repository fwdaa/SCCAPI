using System; 

namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////
    // Интерфейс группы
    ////////////////////////////////////////////////////////////////////////////
    public abstract class Group<E> : IGroup<E>
    {
        // признак нулевого элемента
        public virtual bool IsIdentity(E a) { return a.Equals(Identity); } 
    
        // нулевой и противоположный элемент
        public abstract E Identity { get; } public abstract E Revert(E a);
    
        // сложение элементов
        public abstract E Operation(E a, E b); 
    
        // вычисление кратного элемента
        public abstract E MultiplyOperation(E a, BigInteger e); 
        
        // сумма кратных элементов
        public virtual E MultiplyOperation(E P, BigInteger a, E Q, BigInteger b)
        {
            // проверить корректность данных
            if (a.Signum < 0 || b.Signum < 0) throw new ArgumentException(); 
        
            // определить разрядность большего сомножителя
		    int bits = System.Math.Max(a.BitLength, b.BitLength);

		    // задать начальные условия
		    E R = Identity; E Z = Operation(P, Q);

		    // для всех битов
		    for (int i = bits - 1; i >= 0; i--)
		    {
                // извлечь значение битов
                bool aBit = a.TestBit(i); 
                bool bBit = b.TestBit(i); R = Operation(R, R);
            
                // выполнить вычисления
                if (aBit) R = Operation(R, bBit ? Z : P); 
            
                // выполнить вычисления
                else if (bBit) R = Operation(R, Q);
		    }
		    return R;
        }
    }
}
