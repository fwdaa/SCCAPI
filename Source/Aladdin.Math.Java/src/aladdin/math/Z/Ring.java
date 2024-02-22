package aladdin.math.Z;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Кольцо чисел
///////////////////////////////////////////////////////////////////////////
public class Ring extends aladdin.math.Ring<BigInteger>
{
    private static final long serialVersionUID = -7015677653809575266L;
    
    // экземпляр кольца
    public static final Ring INSTANCE = new Ring(); 
    
    // признак нулевого элемента
    @Override public boolean isZero(BigInteger a) { return a.signum() == 0; }
    
    // нулевой и единичный элементы
    @Override public BigInteger zero() { return BigInteger.ZERO; }
    @Override public BigInteger one () { return BigInteger.ONE;  }
    
    // противоположный элемент
    @Override public BigInteger negate(BigInteger a) { return a.negate(); }
    
    // операции с числами
    @Override public BigInteger add      (BigInteger a, BigInteger b) { return a.add      (b); }
    @Override public BigInteger subtract (BigInteger a, BigInteger b) { return a.subtract (b); }
    @Override public BigInteger multiply (BigInteger a, BigInteger b) { return a.multiply (b); }
    @Override public BigInteger product  (BigInteger a, BigInteger b) { return a.multiply (b); }
    @Override public BigInteger divide   (BigInteger a, BigInteger b) { return a.divide   (b); }
    @Override public BigInteger remainder(BigInteger a, BigInteger b) { return a.remainder(b); }
    
    // вычисление частного и остатка
    @Override public BigInteger[] divideAndRemainder(BigInteger a, BigInteger b)
    {
		// вычисление частного и остатка
		return a.divideAndRemainder(b);
    }
}