package aladdin.math;
import java.math.*; 

////////////////////////////////////////////////////////////////////////////
// Интерфейс группы
////////////////////////////////////////////////////////////////////////////
public abstract class Group<E> implements IGroup<E>
{
    private static final long serialVersionUID = 6152803905290025461L;
    
    // признак нулевого элемента
    @Override public boolean isIdentity(E a) { return a.equals(identity()); } 
    
    // нулевой и противоположный элемент
    @Override public abstract E identity(); @Override public abstract E revert(E a);
    
    // сложение элементов
    @Override public abstract E operation(E a, E b); 
    
    // вычисление кратного элемента
    @Override public abstract E multiply_operation(E a, BigInteger e); 
        
    // сумма кратных элементов
    @Override public final E multiply_operation(E P, BigInteger a, E Q, BigInteger b)
    {
        // проверить корректность данных
        if (a.signum() < 0 || b.signum() < 0) throw new IllegalArgumentException(); 
        
        // определить разрядность большего сомножителя
		int bits = Math.max(a.bitLength(), b.bitLength());

		// задать начальные условия
		E R = identity(); E Z = operation(P, Q);

		// для всех битов
		for (int i = bits - 1; i >= 0; i--)
		{
            // извлечь значение битов
            boolean aBit = a.testBit(i); 
            boolean bBit = b.testBit(i); R = operation(R, R);
            
            // выполнить вычисления
            if (aBit) R = operation(R, bBit ? Z : P); 
            
            // выполнить вычисления
            else if (bBit) R = operation(R, Q);
		}
		return R;
    }
}