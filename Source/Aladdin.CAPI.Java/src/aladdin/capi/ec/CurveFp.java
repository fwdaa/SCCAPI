package aladdin.capi.ec;
import java.security.spec.*; 
import java.math.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////
// Эллиптическая кривая над полем Fp
////////////////////////////////////////////////////////////////////////////
public class CurveFp extends Curve
{
    private static final long serialVersionUID = 6005509912835011602L;
    
    // эллиптическая кривая
    private final aladdin.math.Fp.EllipticCurve ec;
        
    // преобразовать тип кривой
    public static CurveFp convert(java.security.spec.EllipticCurve curve)
    {
        // проверить тип кривой
        if (curve instanceof CurveFp) return (CurveFp)curve; 
        
        // извлечь используемое поле
        ECField ecField = curve.getField(); if (!(ecField instanceof ECFieldFp))
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // выполнить преобразование поля
        FieldFp field = FieldFp.convert((ECFieldFp)ecField); 
                    
        // указать эллиптическую кривую
        return new CurveFp(field, curve.getA(), curve.getB(), curve.getSeed()); 
    }
    // конструктор
    public CurveFp(aladdin.math.Fp.EllipticCurve ec, byte[] seed) 
    {  
        // сохранить переданные параметры
        super(new FieldFp(ec.field().p()), ec.a(), ec.b(), seed); this.ec = ec;
    } 
    // конструктор
    public CurveFp(FieldFp field, BigInteger a, BigInteger b, byte[] seed) 
    { 
        // сохранить переданные параметры
        super(field, a, b, seed); 
        
        // проверить корректность параметров
        if (a.signum() < 0 || b.signum() < 0) throw new IllegalArgumentException();

        // проверить корректность параметров
        if (a.compareTo(field.getP()) >= 0 || b.compareTo(field.getP()) >= 0) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        }
        // указать используемой поле
        aladdin.math.Fp.Field mathField = new aladdin.math.Fp.Field(field.getP()); 

        // создать эллиптическую кривую
        this.ec = new aladdin.math.Fp.EllipticCurve(mathField, a, b);
    } 
    // конструктор
    public CurveFp(BigInteger p, BigInteger a, BigInteger b, byte[] seed) 
    {  
        // сохранить переданные параметры
        super(new FieldFp(p), a, b, seed); 
        
        // указать эллитическую кривую
        this.ec = new aladdin.math.Fp.EllipticCurve(new aladdin.math.Fp.Field(p), a, b);
    } 
    ///////////////////////////////////////////////////////////////////////
    // Свойства эллиптической кривой
    ///////////////////////////////////////////////////////////////////////
    
    // конечное поле
    @Override public final FieldFp getField() { return (FieldFp)super.getField(); }
    
    // признак принадлежности эллиптической кривой
    @Override public final boolean isPoint(ECPoint P)
    {
        // извлечь математическую точку
        aladdin.math.Point<BigInteger> mathPoint = getMathPoint(P); 
        
        // проверить принадлежность точки
        return ec.isPoint(mathPoint); 
    }
    // создать точку на эллиптической кривой
    @Override protected ECPoint createPoint(
        BigInteger x, BigInteger y) throws IOException
    {
        // создать точку на эллиптической кривой
        aladdin.math.Point<BigInteger> mathPoint = 
            new aladdin.math.Point<BigInteger>(x, y); 
        
        // проверить принадлежность точки
        if (!ec.isPoint(mathPoint)) throw new IOException(); 
        
        // вернуть созданную точку
        return new Point<BigInteger>(mathPoint, x, y); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Операции аддитивной группы
    ///////////////////////////////////////////////////////////////////////////
    @Override public final ECPoint negate(ECPoint P)
    {
        // извлечь математическую точку
        aladdin.math.Point<BigInteger> mathPoint = getMathPoint(P); 
        
        // вычислить противоположную точку
        mathPoint = ec.negate(mathPoint); 
        
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<BigInteger>(
            mathPoint, mathPoint.x(), mathPoint.y()
        ); 
    }
    @Override public final ECPoint add(ECPoint P, ECPoint Q)
    {
        // извлечь математические точки
        aladdin.math.Point<BigInteger> mathPointP = getMathPoint(P); 
        aladdin.math.Point<BigInteger> mathPointQ = getMathPoint(Q); 
        
        // вычислить сумму точек
        aladdin.math.Point<BigInteger> mathPoint = ec.add(
            mathPointP, mathPointQ
        ); 
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<BigInteger>(
            mathPoint, mathPoint.x(), mathPoint.y()
        ); 
    }
    @Override public final ECPoint subtract(ECPoint P, ECPoint Q)
    {
        // извлечь математические точки
        aladdin.math.Point<BigInteger> mathPointP = getMathPoint(P); 
        aladdin.math.Point<BigInteger> mathPointQ = getMathPoint(Q); 
        
        // вычислить разность точек
        aladdin.math.Point<BigInteger> mathPoint = ec.subtract(
            mathPointP, mathPointQ
        ); 
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<BigInteger>(
            mathPoint, mathPoint.x(), mathPoint.y()
        ); 
    }
    @Override public final ECPoint twice(ECPoint P)
    {
        // извлечь математическую точку
        aladdin.math.Point<BigInteger> mathPoint = getMathPoint(P); 
        
        // вычислить удвоенную точку
        mathPoint = ec.twice(mathPoint); 

        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<BigInteger>(
            mathPoint, mathPoint.x(), mathPoint.y()
        ); 
    }
    // вычисление кратного элемента
    @Override public final ECPoint multiply(ECPoint P, BigInteger e)
    {
        // извлечь математическую точку
        aladdin.math.Point<BigInteger> mathPoint = getMathPoint(P); 
        
        // вычислить кратный элемент
        mathPoint = ec.multiply(mathPoint, e); 
        
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 

        // вернуть результат
        return new Point<BigInteger>(
            mathPoint, mathPoint.x(), mathPoint.y()
        ); 
    }
    // сумма кратных элементов
    @Override public final ECPoint multiply_sum(
        ECPoint P, BigInteger a, ECPoint Q, BigInteger b)
    {
        // извлечь математические точки
        aladdin.math.Point<BigInteger> mathPointP = getMathPoint(P); 
        aladdin.math.Point<BigInteger> mathPointQ = getMathPoint(Q); 
        
        // вычислить сумму кратных элементов
        aladdin.math.Point<BigInteger> mathPoint = ec.multiply_sum(
            mathPointP, a, mathPointQ, b
        ); 
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<BigInteger>(
            mathPoint, mathPoint.x(), mathPoint.y()
        ); 
    }
    // выполнить преобразование типа
    @SuppressWarnings({"unchecked"}) 
    private aladdin.math.Point<BigInteger> getMathPoint(ECPoint P)
    {
        // проверить на бесконечную точку
        if (isZero(P)) return ec.zero(); 
        
        // выполнить преобразование типа
        if (P instanceof Point) return ((Point<BigInteger>)P).mathPoint(); 
        
        // создать математическую точку
        return new aladdin.math.Point<BigInteger>(P.getAffineX(), P.getAffineY()); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование точек эллиптической кривой
    ///////////////////////////////////////////////////////////////////////////
    
    // вычислить дополнительный бит при сжатии
    @Override protected int compress(ECPoint P)
    {
        // извлечь математическую точку
        aladdin.math.Point<BigInteger> mathPoint = getMathPoint(P); 
        
        // вычислить дополнительный бит при сжатии
        return ec.compress(mathPoint); 
    }
    // вычислить точку кривой при расжатии
    @Override protected ECPoint decompress(BigInteger x, int y0) throws IOException
    {
        try { 
            // вычислить точку кривой при расжатии
            aladdin.math.Point<BigInteger> mathPoint = ec.decompress(x, y0); 

            // проверить на бесконечную точку
            if (ec.isZero(mathPoint)) return zero(); 
            
            // выполнить преобразование типа
            return new Point<BigInteger>(
                mathPoint, mathPoint.x(), mathPoint.y()
            ); 
        }
        // обработать возможное исключение
        catch (ArithmeticException e) { throw new IOException(e); }
    }
}
