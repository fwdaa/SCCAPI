namespace Aladdin.Math.Z
{
    ///////////////////////////////////////////////////////////////////////////
    // Кольцо чисел
    ///////////////////////////////////////////////////////////////////////////
    public class Ring : Ring<BigInteger>
    {
        // экземпляр кольца
        public static readonly Ring Instance = new Ring(); 
    
        // признак нулевого элемента
        public override bool IsZero(BigInteger a) { return a.Signum == 0; }
    
        // нулевой и единичный элементы
        public override BigInteger Zero { get { return BigInteger.Zero; }}
        public override BigInteger One  { get { return BigInteger.One;  }}
    
        // противоположный элемент
        public override BigInteger Negate(BigInteger a) { return a.Negate(); }
    
        // операции с числами
        public override BigInteger Add      (BigInteger a, BigInteger b) { return a.Add      (b); }
        public override BigInteger Subtract (BigInteger a, BigInteger b) { return a.Subtract (b); }
        public override BigInteger Multiply (BigInteger a, BigInteger b) { return a.Multiply (b); }
        public override BigInteger Product  (BigInteger a, BigInteger b) { return a.Multiply (b); }
        public override BigInteger Divide   (BigInteger a, BigInteger b) { return a.Divide   (b); }
        public override BigInteger Remainder(BigInteger a, BigInteger b) { return a.Remainder(b); }
    
        // вычисление частного и остатка
        public override BigInteger[] DivideAndRemainder(BigInteger a, BigInteger b)
        {
		    // вычисление частного и остатка
		    return a.DivideAndRemainder(b);
        }
    }
}