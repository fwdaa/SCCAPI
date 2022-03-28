package aladdin.math.Fp;
import java.math.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Поле по простому модулю (Fp)
///////////////////////////////////////////////////////////////////////////
public class Field extends aladdin.math.Field<BigInteger>
{
    private static final long serialVersionUID = 1037580975082462768L;
    
    // величина модуля
    private final BigInteger p;

    // конструктор
    public Field(BigInteger p) { this.p = p; }

    // вернуть модуль поля
    public final BigInteger p() { return p; }
    
    // сравнение полей
    public final boolean equals(Field other)
    {
        // сравнение полей
        return p.equals(other.p);
    }
    @Override public boolean equals(Object other)
    {
		// проверить совпадение экземпляров
		if (other == this) return true;
			
        // проверить тип элемента
		if (!(other instanceof Field)) return false;
	
        // сравнить значения элементов
		return equals((Field)other);
    }
    // получить хэш-код объекта
    @Override public int hashCode() { return p.hashCode(); }

    ///////////////////////////////////////////////////////////////////////
    // Специальные элементы
    ///////////////////////////////////////////////////////////////////////
    @Override public final boolean isZero(BigInteger a)
    {
		return a.signum() == 0;
    }
    // нулевой и единичный элементы
    @Override public BigInteger zero() { return BigInteger.ZERO; }
    @Override public BigInteger one () { return BigInteger.ONE;  }

    ///////////////////////////////////////////////////////////////////////
    // Операции аддитивной группы
    ///////////////////////////////////////////////////////////////////////
    @Override public final BigInteger negate(BigInteger a)
    {
		// вычислить противоположный элемент
		return p.subtract(a);
    }
    @Override public final BigInteger add(BigInteger a, BigInteger b)
    {
		// сложить с элементом поля
		return a.add(b).mod(p);
    }
    @Override public final BigInteger subtract(BigInteger a, BigInteger b)
    {
        // вычесть элемент поля
        a = a.subtract(b); return (a.signum() >= 0) ? a : a.add(p); 
    }
    @Override public final BigInteger multiply(BigInteger a, BigInteger b)
    {
		// умножить на элемент поля
		return a.multiply(b).mod(p);
    }
    ///////////////////////////////////////////////////////////////////////
    // Операции мультипликативной группы
    ///////////////////////////////////////////////////////////////////////
    @Override public final BigInteger invert(BigInteger a)
    {
		// вычислить обратный элемент
		return a.modInverse(p);
    }
    @Override public final BigInteger product(BigInteger a, BigInteger b)
    {
		// умножить на элемент поля
		return a.multiply(b).mod(p);
    }
    @Override public final BigInteger divide(BigInteger a, BigInteger b)
    {
		// умножить на обратный элемент
		return a.multiply(b.modInverse(p)).mod(p);
    }
    @Override public final BigInteger power(BigInteger a, BigInteger b)
    {
		// возвести в степень
		return a.modPow(b, p);
    }
    ///////////////////////////////////////////////////////////////////////
    // Сгенерировать случайное число
    ///////////////////////////////////////////////////////////////////////
    public BigInteger generate(Random random)
    {
        // проверить наличие генератора
        if (random == null) throw new IllegalArgumentException(); 
        
        // определить требуемое число битов
        int bits = p.bitLength(); BigInteger value;
        
        // выделить буфер для генерации
        byte[] buffer = new byte[(bits + 7) / 8];
        do {
            // сгенерировать случайные данные
            random.nextBytes(buffer);

            // очистить неиспользуемые биты
            if ((bits % 8) != 0) buffer[0] &= (1 << (bits % 8)) - 1; 
        
            // создать большое число 
            value = new BigInteger(1, buffer);
        }
        // проверить выполнение условий генерации
        while (value.compareTo(p) >= 0); return value; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Вычисление z квадратного корня z^2 = g (второй корень = p - z)
    // Генератор случайных данных используется при p = 8u + 1
    ///////////////////////////////////////////////////////////////////////
    public BigInteger sqrt(BigInteger g)
    {
        // для p = 4u + 3
        if (p.testBit(1)) { BigInteger u = p.shiftRight(2); 
        
            // вычислить y = g^{u + 1} mod p
            BigInteger y = power(g, u.add(BigInteger.ONE)); 
            
            // проверить y^2 = g mod p
            return (sqr(y).equals(g)) ? y :  null; 
        }
        // для p = 8u + 5
        else if (p.testBit(2)) { BigInteger u = p.shiftRight(3); 
        
            // вычислить gamma = (2g)^u mod p
            BigInteger g2 = twice(g); BigInteger gamma = power(g2, u); 
            
            // вычислить i = (2g)gamma^2 mod p
            BigInteger i = product(g2, sqr(gamma)); 
            
            // вычислить y = g gamma (i-1) mod p
            BigInteger y = product(product(g, gamma), subtract(i, BigInteger.ONE)); 

            // проверить y^2 = g mod p
            return (sqr(y).equals(g)) ? y : null; 
        }
        // для p = 4u + 1
        else { BigInteger u2_1 = p.shiftRight(1).add(BigInteger.ONE); 
        
            // указать начальные условия
            BigInteger[] UV; BigInteger Q4 = multiply(g, BigInteger.valueOf(4)); 
            do {
                // сгенерировать случайное число
                BigInteger P = BigInteger.ZERO; while (isZero(P)) P = generate(new Random()); 
                
                // вычислить (2u + 1)-элемент Лукаса 
                BigInteger Q = g; UV = lucasSequence(P, Q, u2_1); 
                
                // при выполнении условия U = 0 или V^2 = 4Q (mod p)
                if (isZero(UV[0]) || sqr(UV[1]).equals(Q4)) 
                {
                    // выполнить деление на два
                    if (UV[1].testBit(0)) UV[1] = UV[1].add(p); return UV[1].shiftRight(1);                    
                }
            }
            // проверить условие 
            while (!isZero(UV[1])); 
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Последовательность Лукаса
    ///////////////////////////////////////////////////////////////////////
    // U0 = 0, U1 = 1, U_{k} = P U_{k-1} - Q U_{k-2}
    // V0 = 2, V1 = P, V_{k} = P V_{k-1} - Q V_{k-2}
    ///////////////////////////////////////////////////////////////////////
    private BigInteger[] lucasSequence(BigInteger P, BigInteger Q, BigInteger k) 
    {
        // вычислить delta = P^2 - 4Q
        BigInteger delta = subtract(sqr(P), multiply(Q, BigInteger.valueOf(4))); 
        
        // указать начальные условия
        BigInteger U = BigInteger.ONE; BigInteger V = P; 
        
        // для всех битов
        for (int i = k.bitLength() - 2; i >= 0; i--)
        {
            // выполнить вычисления
            boolean bit = k.testBit(i); BigInteger T = product(U, V); 
            
            // выполнить вычисления
            V = add(sqr(V), product(delta, sqr(U))); U = T;
            
            // выполнить деление на два
            if (V.testBit(0)) V = V.add(p); V = V.shiftRight(1); 
            
            // выполнить вычисления
            if (bit) { T = add(product(P, U), V); 
            
                // выполнить деление на два
                if (T.testBit(0)) T = T.add(p); T = T.shiftRight(1); 
            
                // выполнить вычисления
                V = add(product(P, V), product(delta, U)); U = T;
                
                // выполнить деление на два
                if (V.testBit(0)) V = V.add(p); V = V.shiftRight(1); 
            }
        }
        // вернуть результат
        return new BigInteger[] { U, V }; 
    }
}
