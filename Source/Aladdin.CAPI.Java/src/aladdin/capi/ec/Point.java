package aladdin.capi.ec;
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Точка на эллиптической кривой
///////////////////////////////////////////////////////////////////////////////
class Point<E> extends java.security.spec.ECPoint implements Serializable
{
    private static final long serialVersionUID = -3706793941882739739L;
    
    // точка на эллиптической кривой
    private final aladdin.math.Point<E> mathPoint; 
    
    // конструктор
    public Point(aladdin.math.Point<E> mathPoint, BigInteger x, BigInteger y)
    {
        // сохранить переданные параметры
        super(x, y); this.mathPoint = mathPoint; 
    }
    // точка на эллиптической кривой
    public final aladdin.math.Point<E> mathPoint() { return mathPoint; } 
}
