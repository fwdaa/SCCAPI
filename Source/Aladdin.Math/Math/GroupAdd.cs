using System; 

namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////
    // Аддитивная группа (умножение NAF)
    ////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public abstract class GroupAdd<E> : Group<E>, IGroupAdd<E>
    {
        // признак нулевого элемента
        public virtual bool IsZero(E a) { return a.Equals(Zero); } 
    
        // нулевой и противоположный элемент
        public abstract E Zero { get; } public abstract E Negate(E a);
    
        // сложение элементов
        public abstract E Add(E a, E b); 
 
        // вычитание элементов
        public virtual E Subtract(E a, E b) { return IsZero(b) ? a : Add(a, Negate(b)); }
        
        // удвоение элемента
        public virtual E Twice(E a) { return Add(a, a); }
        
        // вычисление кратного элемента
        public virtual E Multiply(E a, BigInteger e) { return MultiplyOperation(a, e); }
    
        // сумма кратных элементов
        public virtual E MultiplySum(E P, BigInteger a, E Q, BigInteger b)
        {
            // сумма кратных элементов
            return MultiplyOperation(P, a, Q, b); 
        }
        // признак нулевого элемента
        public override bool IsIdentity(E a) { return IsZero(a); } 

        // нулевой элемент
        public override E Identity { get { return Zero; }} 
        
        // противоположный элемент
        public override E Revert(E a) { return Negate(a); } 
        
        // сложение элементов
        public override E Operation(E a, E b) { return Add(a, b); } 

        // вычисление кратного элемента
        public override E MultiplyOperation(E a, BigInteger e) 
        { 
            // проверить необходимость вычислений   
            if (IsIdentity(a) || e.Signum == 0) return Identity; 

            // обработать отрицательный сомножитель
            if (e.Signum < 0) return Revert(MultiplyOperation(a, e.Abs())); E r = a; 
        
            // выполнить умножение на 3
            BigInteger h = e.Multiply(BigInteger.ValueOf(3)); E n = Revert(a);
        
            // для всех битов
            for (int i = h.BitLength - 2; i > 0; i--)
            {
                // выполнить вычисления
                bool hBit = h.TestBit(i); r = Twice(r); 

                // выполнить вычисления
                if (hBit != e.TestBit(i)) r = Operation(r, hBit ? a : n);
            }
            return r;
        } 
    }
}
