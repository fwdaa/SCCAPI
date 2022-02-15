package aladdin.capi.retro.java.security.spec;
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Конечное поле F_{2^m}
///////////////////////////////////////////////////////////////////////////////
public class ECFieldF2m implements ECField 
{
    // разрядность поля и образующий многочлен
    private final int m; private final BigInteger rp;

    // конструктор 
    public ECFieldF2m(int m) 
    {
        // проверить корректность параметров
        if (m <= 0) throw new IllegalArgumentException("m is not positive");
        
        // сохранить переданные параметры
        this.m = m; this.rp = null;
    }
    public ECFieldF2m(int m, BigInteger rp) 
    {
        // проверить корректность параметров
        if (m <= 0) throw new IllegalArgumentException("m is not positive");
        
        // проверить корректность параметров
        if (!rp.testBit(0) || !rp.testBit(m)) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(
                "rp does not represent a valid reduction polynomial"
            );
        }
        // сохранить переданные параметры
        this.m = m; this.rp = rp;
    }
    // разрядность поля
    public int getFieldSize() { return m; }
    public int getM        () { return m; }

    // образующий многочлен
    public BigInteger getReductionPolynomial() { return rp; }
    
    // сравнить объекты
    public boolean equals(Object obj) 
    {
        // проверить совпадение ссылок
        if (this == obj)  return true;

        // проверить тип объекта
        if (!(obj instanceof ECFieldF2m)) return false; 
        
        // сравнить разрядность поля
        if (m != ((ECFieldF2m)obj).m) return false; 
        
        // проверить наличие нормального базиса
        if (rp == null) return ((ECFieldF2m)obj).rp == null; 
        
        // сравнить образующие многочлены
        return rp.equals(((ECFieldF2m)obj).rp);
    }
    // хэш-код объекта
    public int hashCode() 
    { 
        // вычислить хэш-код объекта
        if (rp == null) return m << 5; 
        
        // вычислить хэш-код объекта
        return rp.hashCode() + (m << 5); 
    }
}
