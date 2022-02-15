package aladdin.capi.retro.java.security.spec;
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Эллиптипческая кривая
///////////////////////////////////////////////////////////////////////////////
public class EllipticCurve 
{
    // конечное поле и параметры генерации
    private final ECField field; private final byte[] seed;
    
    // коэффициенты уравнения
    private final BigInteger a; private final BigInteger b;
    
    // конструктор
    public EllipticCurve(ECField field, BigInteger a, BigInteger b) 
    {
        // сохранить переданные параметры
        this(field, a, b, null);
    }
    // конструктор
    public EllipticCurve(ECField field, BigInteger a, BigInteger b, byte[] seed) 
    {
        // проверить наличие параметров
        if (field == null) throw new NullPointerException("field is null"             );
        if (a     == null) throw new NullPointerException("first coefficient is null" );
        if (b     == null) throw new NullPointerException("second coefficient is null");
        
        // для простого поля
        if (field instanceof ECFieldFp) 
        {
            // получить величину модуля
            BigInteger p = ((ECFieldFp)field).getP();
            
            if (a.signum() < 0) throw new IllegalArgumentException("first coefficient is negative");
            if (b.signum() < 0) throw new IllegalArgumentException("second coefficient is negative");
            
            // проверить корректность параметров
            if (p.compareTo(a) != 1) throw new IllegalArgumentException("first coefficient is too large");
            if (p.compareTo(b) != 1) throw new IllegalArgumentException("second coefficient is too large");
        } 
        // для поля многочленов
        else if (field instanceof ECFieldF2m) 
        {
            // получить разрядность поля
            int m = ((ECFieldF2m)field).getM();
            
            // проверить корректность параметров
            if (a.bitLength() > m) throw new IllegalArgumentException("first coefficient is too large");
            if (b.bitLength() > m) throw new IllegalArgumentException("second coefficient is too large");
        }
        // сохранить переданные параметры
        this.field = field; this.a = a; this.b = b;
        
        // сохранить переданные параметры
        this.seed = (byte[])((seed != null) ? seed.clone() : null); 
    }
    // конечное поле
    public ECField getField() { return field; }

    // коэффициенты уравнения
    public BigInteger getA() { return a; }
    public BigInteger getB() { return b; }

    // параметры генерации
    public byte[] getSeed() 
    {
        // параметры генерации
        return (byte[])((seed != null) ? seed.clone() : null); 
    }
    // сравнить объекты
    public boolean equals(Object obj) 
    {
        // проверить совпадение ссылок
        if (this == obj) return true;
        
        // проверить тип объекта
        if (!(obj instanceof EllipticCurve)) return false; 
        
        // выполнить преобразование типа
        EllipticCurve curve = (EllipticCurve) obj;
        
        // сравнить используемые поля 
        if (!field.equals(curve.field)) return false; 
        
        // сравнить коэффициенты уравнения
        return (a.equals(curve.a) && b.equals(curve.b)); 
    }
    // хэш-код объекта
    public int hashCode() 
    { 
        // хэш-код объекта
        return (field.hashCode() << 6) + (a.hashCode() << 4) + (b.hashCode() << 2);
    }
}
