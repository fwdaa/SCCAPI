package aladdin.capi.ec;
import aladdin.math.*;
import aladdin.util.*;
import java.security.spec.*; 
import java.math.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// Эллиптическая кривая
////////////////////////////////////////////////////////////////////////////////
public abstract class Curve extends java.security.spec.EllipticCurve 
{
    // преобразовать тип кривой
    public static Curve convert(java.security.spec.EllipticCurve curve)
    {
        // проверить тип кривой
        if (curve instanceof Curve) return (Curve)curve; 
        
        // в зависимости от типа поля
        if (curve.getField() instanceof ECFieldFp)
        {
            // преобразовать тип кривой
            return CurveFp.convert(curve); 
        }
        // преобразовать тип кривой
        else return CurveF2m.convert(curve); 
    }
    // конструктор
    protected Curve(ECField field, BigInteger a, BigInteger b, byte[] seed) 
    {
        // сохранить переданные параметры
        super(field, a, b, seed); 
    }
    // конструктор
    protected Curve(ECField field, BigInteger a, BigInteger b) 
    {
        // сохранить переданные параметры
        super(field, a, b); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Свойства эллиптической кривой
    ///////////////////////////////////////////////////////////////////////
    
    // признак принадлежности эллиптической кривой
    public abstract boolean isPoint(ECPoint P); 
    
    // создать точку на эллиптической кривой
    protected abstract ECPoint createPoint(BigInteger x, BigInteger y) throws IOException; 
    
    ///////////////////////////////////////////////////////////////////////////
    // Операции аддитивной группы
    ///////////////////////////////////////////////////////////////////////////

    // признак нулевого элемента
    public final boolean isZero(ECPoint P) { return P == Point.POINT_INFINITY; }
    // нулевой элемент
    public final ECPoint zero() { return Point.POINT_INFINITY; } 

    // противоположный элемент
    public abstract ECPoint negate(ECPoint P); 

    // сложение и вычитание элементов
    public abstract ECPoint add     (ECPoint P, ECPoint Q);
    public abstract ECPoint subtract(ECPoint P, ECPoint Q); 
    // удвоение элемента
    public abstract ECPoint twice(ECPoint P); 

    // вычисление кратного элемента 
    public abstract ECPoint multiply(ECPoint P, BigInteger e); 
    // сумма кратных элементов
    public abstract ECPoint multiply_sum(
        ECPoint P, BigInteger a, ECPoint Q, BigInteger b
    ); 
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование точек эллиптической кривой
    ///////////////////////////////////////////////////////////////////////////
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 

    // закодировать точку
    public final byte[] encode(ECPoint P, Encoding encoding)
    {
        // проверить на бесконечность
        if (isZero(P)) return new byte[] { 0x00 }; 
        
        // определить размер закодированных представлений
        int cb = (getField().getFieldSize() + 7) / 8; switch (encoding)
        {
        case UNCOMPRESSED: case DEFAULT: 
        {
            // закодировать координаты X и Y
            byte[] X1 = Convert.fromBigInteger(P.getAffineX(), ENDIAN, cb); 
            byte[] Y1 = Convert.fromBigInteger(P.getAffineY(), ENDIAN, cb);
            
            // вернуть закодированное представление
            return Array.concat(new byte[] { 0x04 }, X1, Y1); 
        }
        case COMPRESSED: 
        {
            // вычислить дополнительный бит
            byte[] PC = new byte[] { compress(P) == 0 ? (byte)0x02 : (byte)0x03 }; 
            
            // вернуть закодированное представление
            return Array.concat(PC, Convert.fromBigInteger(P.getAffineX(), ENDIAN, cb)); 
        }
        case HYBRID: 
        {
            // вычислить дополнительный бит
            byte[] PC = new byte[] { compress(P) == 0 ? (byte)0x06 : (byte)0x07 }; 
            
            // закодировать координаты X и Y
            byte[] X1 = Convert.fromBigInteger(P.getAffineX(), ENDIAN, cb); 
            byte[] Y1 = Convert.fromBigInteger(P.getAffineY(), ENDIAN, cb);

            // вернуть закодированное представление
            return Array.concat(PC, X1, Y1); 
        }}
        return null; 
    }
    // раскодировать точку
    public final ECPoint decode(byte[] encoded) throws IOException
    {
        // раскодировать точку
        return decode(encoded, Encoding.DEFAULT); 
    }
    // раскодировать точку
    public final ECPoint decode(byte[] encoded, Encoding encoding) throws IOException
    {
        // проверить корректность данных
        if (encoded.length == 0) throw new IOException(); switch (encoded[0])
        {
        case 0x00:
        {
            // вернуть бесконечно удаленную точку
            if (encoded.length != 1) throw new IOException(); return zero(); 
        }
        case 0x02: case 0x03:
        {
            // проверить тип кодирования
            if (encoding != Encoding.DEFAULT && encoding != Encoding.COMPRESSED)
            {
                throw new IOException(); 
            }
            // раскодировать координату X
            BigInteger X = Convert.toBigInteger(encoded, 1, encoded.length - 1, ENDIAN); 
             
            // создать точку эллиптической кривой
            return decompress(X, encoded[0] - 0x02);
        }
        case 0x04:
        {
            // проверить тип кодирования
            if (encoding != Encoding.DEFAULT && encoding != Encoding.UNCOMPRESSED)
            {
                throw new IOException(); 
            }
            // проверить корректность размера
            if ((encoded.length & 1) == 0) throw new IOException(); 
            
            // вычислить размер каждой координаты
            int length = (encoded.length - 1) / 2; 
            
            // раскодировать координаты
            BigInteger X = Convert.toBigInteger(encoded, 1         , length, ENDIAN); 
            BigInteger Y = Convert.toBigInteger(encoded, 1 + length, length, ENDIAN); 
            
            // создать точку эллиптической кривой
            return createPoint(X, Y);
        }
        case 0x06: case 0x07:
        {
            // проверить тип кодирования
            if (encoding != Encoding.DEFAULT && encoding != Encoding.HYBRID)
            {
                throw new IOException(); 
            }
            // проверить корректность размера
            if ((encoded.length & 1) == 0) throw new IOException(); 
            
            // вычислить размер каждой координаты
            int length = (encoded.length - 1) / 2; 
            
            // раскодировать координаты
            BigInteger X = Convert.toBigInteger(encoded, 1         , length, ENDIAN); 
            BigInteger Y = Convert.toBigInteger(encoded, 1 + length, length, ENDIAN); 
            
            // создать точку эллиптической кривой
            ECPoint P = createPoint(X, Y); 
            
            // проверить корректность данных
            if (compress(P) != encoded[0] - 0x06) throw new IOException(); return P;  
        }}
        throw new IOException(); 
    }
    // вычислить дополнительный бит при сжатии
    protected abstract int compress(ECPoint P); 
    
    // вычислить точку кривой при расжатии
    protected abstract ECPoint decompress(BigInteger x, int y0) throws IOException; 
}
