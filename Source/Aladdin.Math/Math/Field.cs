using System; 

namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////
    // Интерфейс поля
    ////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public abstract class Field<E> : Ring<E>, IField<E>
    {
        // размерность поля
        public abstract int Dimension { get; }

        // вычислить обратный элемент
        public abstract E Invert(E a);
              
        // умножить на обратный элемент
        public override E Divide(E a, E b)  
        {
            // умножить на обратный элемент
            return (IsOne(b)) ? a : Product(a, Invert(b)); 
        }
        // вычисление степени элемента 
        public override E Power(E a, BigInteger e)
        {
            // обработать отрицательный сомножитель
            if (e.Signum < 0) return Invert(Power(a, e.Abs())); 
        
            // вызвать базовую функцию
            return base.Power(a, e); 
        }
        // произведение степеней элементов 
        public override E PowerProduct(E P, BigInteger a, E Q, BigInteger b)
        {
            // проверить корректность данных
            if (a.Signum < 0) { P = Invert(P); a = a.Abs(); }
            if (b.Signum < 0) { Q = Invert(Q); b = b.Abs(); }
        
            // вызвать базовую функцию
            return base.PowerProduct(P, a, Q, b); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Операции кольца
        ///////////////////////////////////////////////////////////////////////
        public override E Remainder (E a, E b) { return Zero; } 
    
        // вычисление частного и остатка
        public override E[] DivideAndRemainder(E a, E b)
        {
            // вычисление частного и остатка
            return new E[2] { Divide(a, b), Zero }; 
        }
    }
}