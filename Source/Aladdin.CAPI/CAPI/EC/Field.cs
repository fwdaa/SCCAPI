namespace Aladdin.CAPI.EC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Конечное поле 
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class Field : Math.IField<Math.BigInteger>
    {
        // разрядность поля
        public abstract int FieldSize { get; }

        ///////////////////////////////////////////////////////////////////////////
        // Операции аддитивной группы
        ///////////////////////////////////////////////////////////////////////////

        // признак нулевого элемента
        public abstract bool IsZero(Math.BigInteger P);
        // нулевой элемент
        public abstract Math.BigInteger Zero { get; }
    
        // противоположный и удвоенный элемент
        public abstract Math.BigInteger Negate(Math.BigInteger P); 
        public abstract Math.BigInteger Twice (Math.BigInteger P); 
    
        // сложение элементов
        public abstract Math.BigInteger Add     (Math.BigInteger P, Math.BigInteger Q); 
        public abstract Math.BigInteger Subtract(Math.BigInteger P, Math.BigInteger Q); 

        // вычисление кратного элемента
        public abstract Math.BigInteger Multiply(Math.BigInteger P, Math.BigInteger e); 

        // сумма кратных элементов
        public abstract Math.BigInteger MultiplySum(Math.BigInteger P, 
            Math.BigInteger a, Math.BigInteger Q, Math.BigInteger b
        ); 
        ///////////////////////////////////////////////////////////////////////////
        // Операции мультипликативной группы
        ///////////////////////////////////////////////////////////////////////////
    
        // признак единичного элемента
        public abstract bool IsOne(Math.BigInteger P); 
        // единичный элемент
        public abstract Math.BigInteger One { get; } 
    
        // обратный и возведенный в квадрат элемент
        public abstract Math.BigInteger Invert(Math.BigInteger P);
        public abstract Math.BigInteger Sqr   (Math.BigInteger P);
    
        // умножение и деление элементов
        public abstract Math.BigInteger Product(Math.BigInteger P, Math.BigInteger Q); 
        public abstract Math.BigInteger Divide (Math.BigInteger P, Math.BigInteger Q); 

        // возведение в степень элемента
        public abstract Math.BigInteger Power(Math.BigInteger P, Math.BigInteger e); 

        // умножение возведенных в степень элементов
        public abstract Math.BigInteger PowerProduct(Math.BigInteger P, 
            Math.BigInteger a, Math.BigInteger Q, Math.BigInteger b
        ); 
    }
}
