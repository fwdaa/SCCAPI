package aladdin.math.F2m;
import aladdin.math.PZ.Ring;
import aladdin.math.*;

///////////////////////////////////////////////////////////////////////////
// Поле многочленов (F_{2^m}) в полиномиальном базисе
// Многочлен a(x) = a_0 x^{m-1} + ... + a_{m-2} x + a_{m-1}
///////////////////////////////////////////////////////////////////////////
public class PolyField extends Field
{
    private static final long serialVersionUID = 5019732556118149277L;
    
    // образующий многочлен и единичный элемент
    private final Polynom polynom; private final Vector one;

    // конструктор
    public PolyField(Polynom polynom) 
    { 
        // сохранить переданные параметры
        super(polynom.bitLength() - 1); this.polynom = polynom; 
        
        // создать единичный элемент
        VectorBuilder builder = new VectorBuilder(m()); 
        
        // указать единичный элементы
        builder.set(m() - 1, 1); this.one = builder.toVector(); 
    }
    // вернуть многочлен поля
    public final Polynom polynom() { return polynom; }

    // сравнение полей
    public final boolean equals(PolyField other)
    {
        // сравнение полей
		return polynom.equals(other.polynom);
    }
    // сравнение полей
    @Override public boolean equals(Object other)
    {
        // проверить совпадение экземпляров
		if (other == this) return true;

        // проверить тип элемента
		if (!(other instanceof PolyField)) return false;

		// сравнить значения элементов
		return equals((PolyField)other);
    }
    // получить хэш-код объекта
    @Override public int hashCode() { return polynom.hashCode(); }

    //////////////////////////////////////////////////////////////////////
    // Операции мультипликативной группы
    ///////////////////////////////////////////////////////////////////////
    @Override public final Vector one () { return one; }

    @Override public final Vector invert(Vector a)
    {
        // выполнить расширенный алгоритм Евклида
        Polynom[] euclid = Ring.INSTANCE.euclid(a.toPolynom(), polynom); 
        
        // проверить наличие обратного элемента
        Polynom U = euclid[1]; if (!euclid[0].equals(Polynom.ONE))
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException("GCD != 1"); 
        }
		// выполнить дополнительное приведение
        if (U.bitLength() == polynom.bitLength()) U = U.add(polynom);
        
        // вернуть результат
        return U.toVector(m()); 
    }
    @Override public final Vector product(Vector a, Vector b)
    {
        // выполнить преобразование типа
        Polynom polynomA = a.toPolynom(); Polynom polynomB = b.toPolynom(); 
        
		// выполнить умножение многочленов
		return polynomA.product(polynomB).remainder(polynom).toVector(m());
    }
    //////////////////////////////////////////////////////////////////////
    // Специальные функции
    ///////////////////////////////////////////////////////////////////////
    @Override public final int trace(Vector a) { Vector T = a; 
        
        // выполнить вычисления
        for (int i = 1; i < m(); i++) T = add(sqr(T), a); return T.get(m() - 1); 
    }
    public final Vector half_trace(Vector a) { Vector T = a; 
        
        // проверить корректность параметров
        if ((m() & 1) == 0) throw new IllegalArgumentException(); 
    
        // выполнить ычисления
        for (int i = 1; i <= (m() - 1) / 2; i++) T = add(sqr(sqr(T)), a); return T; 
    }
    //////////////////////////////////////////////////////////////////////
    // Корень z квадратного уравнения z^2 + z = beta 
    // Генератор случайных данных используется при четном m
    //////////////////////////////////////////////////////////////////////
    @Override public final Vector quadratic_root(Vector beta)
    { 
        // обработать тривиальный случай
        if (isZero(beta)) return beta; if ((m() & 1) != 0)
        {
            // выполнить вычисления
            Vector z = half_trace(beta); Vector gamma = add(sqr(z), z);
            
            // вернуть квадратный корень
            return (gamma.equals(beta)) ? z : null; 
        }
        else { 
            // указать генератор слуайных данных
            java.util.Random random = new java.util.Random(); Vector z;
            do {
                // сгенерировать случайный элемент
                Vector tau = generate(random); Vector w = beta; z = zero(); 

                // требуемое число раз
                for (int i = 1; i < m(); i++)
                {
                    // выполнить вычисления
                    z = add(sqr(z), product(sqr(w), tau));

                    // выполнить вычисления
                    w = add(sqr(w), beta); 
                }
                // проверить наличие корней
                if (!isZero(w)) return null; 
            }
            // проверить условие 
            while (isZero(add(sqr(z), z))); return z; 
        }
    }
}