package aladdin.math.PZ;
import aladdin.math.*;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Кольцо многочленов
///////////////////////////////////////////////////////////////////////////
public class Ring extends aladdin.math.Ring<Polynom>
{
    private static final long serialVersionUID = -4597188960298450026L;
    
    // экземпляр кольца
    public static final Ring INSTANCE = new Ring(); 

    // признак нулевого элемента
    @Override public boolean isZero(Polynom a) { return a.isZero(); }

    // нулевой и единичный элементы
    @Override public Polynom zero() { return Polynom.ZERO; }
    @Override public Polynom one () { return Polynom.ONE;  }

    // противоположный элемент
    @Override public Polynom negate(Polynom a) { return a; }
    
    // вычисление кратного элемента
    @Override public Polynom multiply (Polynom a, BigInteger e) 
    { 
        // вычисление кратного элемента
        return e.testBit(0) ? a : zero(); 
    }
    // операции с многочленами
    @Override public Polynom add      (Polynom a, Polynom b) { return a.add      (b); }
    @Override public Polynom subtract (Polynom a, Polynom b) { return a.add      (b); }
    @Override public Polynom product  (Polynom a, Polynom b) { return a.product (b); }
    @Override public Polynom divide   (Polynom a, Polynom b) { return a.divide   (b); }
    @Override public Polynom remainder(Polynom a, Polynom b) { return a.remainder(b); }

    // вычисление частного и остатка
    @Override
    public Polynom[] divideAndRemainder(Polynom a, Polynom b)
    {
        // вычисление частного и остатка
		return a.divideAndRemainder(b);
    }
}