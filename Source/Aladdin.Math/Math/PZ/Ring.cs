using System; 

namespace Aladdin.Math.PZ
{
    ///////////////////////////////////////////////////////////////////////////
    // Кольцо многочленов
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class Ring : Ring<Polynom>
    {
        // экземпляр кольца
        public static readonly Ring Instance = new Ring(); 

        // признак нулевого элемента
        public override bool IsZero(Polynom a) { return a.IsZero; }

        // нулевой и единичный элементы
        public override Polynom Zero { get { return Polynom.Zero; }}
        public override Polynom One  { get { return Polynom.One;  }}

        // противоположный элемент
        public override Polynom Negate(Polynom a) { return a; }
    
        // вычисление кратного элемента
        public override Polynom Multiply (Polynom a, BigInteger e) 
        { 
            // вычисление кратного элемента
            return e.TestBit(0) ? a : Zero; 
        }
        // операции с многочленами
        public override Polynom Add      (Polynom a, Polynom b) { return a.Add      (b); }
        public override Polynom Subtract (Polynom a, Polynom b) { return a.Add      (b); }
        public override Polynom Product  (Polynom a, Polynom b) { return a.Product  (b); }
        public override Polynom Divide   (Polynom a, Polynom b) { return a.Divide   (b); }
        public override Polynom Remainder(Polynom a, Polynom b) { return a.Remainder(b); }

        // вычисление частного и остатка
        public override Polynom[] DivideAndRemainder(Polynom a, Polynom b)
        {
            // вычисление частного и остатка
		    return a.DivideAndRemainder(b);
        }
    }
}