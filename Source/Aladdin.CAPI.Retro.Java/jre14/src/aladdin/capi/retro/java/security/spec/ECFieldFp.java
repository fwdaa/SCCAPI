package aladdin.capi.retro.java.security.spec;
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Конечное поле Fp
///////////////////////////////////////////////////////////////////////////////
public class ECFieldFp implements ECField 
{
    // значение модуля
    private final BigInteger p;

    // конструктор
    public ECFieldFp(BigInteger p) { this.p = p; 
    
        // проверить корректность параметров
        if (p.signum() != 1) throw new IllegalArgumentException("p is not positive");
    }
    // разрядность поля
    public int getFieldSize() { return p.bitLength(); };

    // значение модуля
    public BigInteger getP() { return p; }

    // сравнить объекты
    public boolean equals(Object obj) 
    {
        // проверить совпадение ссылок
        if (this == obj)  return true;
        
        // проверить тип объекта
        if (!(obj instanceof ECFieldFp)) return false; 
        
        // сравнить модули
        return p.equals(((ECFieldFp)obj).p);
    }
    // хэш-код объекта
    public int hashCode() { return p.hashCode(); }
}
