namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////
    // Мультипликативная группа (умножение скользящим окном)
    ////////////////////////////////////////////////////////////////////////////
    public abstract class GroupMul<E> : Group<E>, IGroupMul<E>
    {
        // признак единичного элемента
        public virtual bool IsOne(E a) { return a.Equals(One); } 
    
        // единичный и обратный элемент
        public abstract E One { get; } public abstract E Invert(E a);
    
        // умножение элементов
        public abstract E Product(E a, E b); 
 
        // деление элементов
        public virtual E Divide(E a, E b) { return IsOne(b) ? a : Product(a, Invert(b)); }
        
        // возведение в квадрат
        public virtual E Sqr(E a) { return Product(a, a); }
        
        // возведение в степень 
        public virtual E Power(E a, BigInteger e) { return MultiplyOperation(a, e); }
    
        // произведение степеней элементов 
        public E PowerProduct(E P, BigInteger a, E Q, BigInteger b)
        {
            // сумма кратных элементов
            return MultiplyOperation(P, a, Q, b); 
        }
        // признак нулевого элемента
        public override bool IsIdentity(E a) { return IsOne(a); } 

        // нулевой элемент
        public override E Identity { get { return One; }}
        
        // противоположный элемент
        public override E Revert(E a) { return Invert(a); } 
        
        // сложение элементов
        public override E Operation(E a, E b) { return Product(a, b); } 

        // возведение в степень 
        public override E MultiplyOperation(E a, BigInteger e) 
        { 
            // проверить необходимость вычислений
            if (IsIdentity(a) || e.Signum == 0) return Identity; 

            // обработать отрицательный сомножитель
            if (e.Signum < 0) return Revert(MultiplyOperation(a, e.Abs())); E r = a; 
        
            // для всех битов
            for (int i = e.BitLength - 2; i >= 0; i--)
            {
                // выполнить вычисления
                r = Sqr(r); if (e.TestBit(i)) r = Operation(r, a);
            }
            return r;
        }
    }
}