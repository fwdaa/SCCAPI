package aladdin.math.F2m;
import aladdin.math.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////////
// Поле многочленов (F_{2^m})
///////////////////////////////////////////////////////////////////////////
public abstract class Field extends aladdin.math.Field<Vector>
{
    private static final long serialVersionUID = 2028930922515454354L;
    
    // нулевой элемент
    private final Vector zero; 

    // конструктор
    public Field(int m) { zero = Vector.zeros(m); }
    
    // вернуть размерность поля 
    public final int m() { return zero.m(); } 
    
    ///////////////////////////////////////////////////////////////////////
    // Операции аддитивной группы
    ///////////////////////////////////////////////////////////////////////
    @Override public final Vector zero() { return zero; }

    @Override public final Vector negate(Vector a) { return a;      }
    @Override public final Vector twice (Vector a) { return zero(); } 
    
    @Override public final Vector add     (Vector a, Vector b) { return a.add(b); }
    @Override public final Vector subtract(Vector a, Vector b) { return a.add(b); }

    // вычисление кратного элемента
    @Override public final Vector multiply(Vector a, BigInteger e) 
    { 
        // вычисление кратного элемента
        return e.testBit(0) ? a : zero(); 
    }
    // вычисление квадратного корня
    public Vector sqrt(Vector a) { Vector r = a; 
        
        // вычислить a^{2^{m-1}}
        for (int i = 0; i < m() - 1; i++) r = sqr(r); return r; 
    } 
    ///////////////////////////////////////////////////////////////////////
    // Сгенерировать случайное число
    ///////////////////////////////////////////////////////////////////////
    public Vector generate(java.util.Random random)
    {
        // сгенерировать случайное число
        return new Vector(random, m());
    }
    ///////////////////////////////////////////////////////////////////////
    // Специальные функции
    ///////////////////////////////////////////////////////////////////////
    public abstract int trace(Vector a);  

    // корень z уравнения z^2 + z = beta (второй корень = z + 1)
    public abstract Vector quadratic_root(Vector beta);  
}