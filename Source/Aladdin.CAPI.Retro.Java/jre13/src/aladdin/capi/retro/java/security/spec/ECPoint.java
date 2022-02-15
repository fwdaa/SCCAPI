package aladdin.capi.retro.java.security.spec;
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Точка на эллиптической кривой
///////////////////////////////////////////////////////////////////////////////
public class ECPoint 
{
    // координаты точки на эллиптической кривой
    private final BigInteger x; private final BigInteger y;

    // бесконечно удаленная точка
    public static final ECPoint POINT_INFINITY = new ECPoint();

    // бесконечно удаленная точка
    private ECPoint() { this.x = null; this.y = null; }

    // конструктор
    public ECPoint(BigInteger x, BigInteger y) 
    {
        // проверить корректность параметров
        if (x == null || y == null) throw new NullPointerException("affine coordinate x or y is null");
        
        // сохранить переданные параметры
        this.x = x; this.y = y;
    }
    // координаты точки
    public BigInteger getAffineX() { return x; }
    public BigInteger getAffineY() { return y; }

    // сравнение объектов
    public boolean equals(Object obj) 
    {
        // проверить совпадение ссылок
        if (this == obj) return true;
        
        // проверить на бесконечно удаленную точку
        if (this == POINT_INFINITY) return false;
        
        // проверить тип объекта
        if (!(obj instanceof ECPoint)) return false; 
        
        // сравнить координаты точек
        return (x.equals(((ECPoint)obj).x) && y.equals(((ECPoint)obj).y));
    }
    // хэш-код объекта
    public int hashCode() 
    {
        // хэш-код бесконечно удаленной точки
        if (this == POINT_INFINITY) return 0;
        
        // вычислить хэш-код объекта
        return (x.hashCode() << 5) + y.hashCode();
    }
}
