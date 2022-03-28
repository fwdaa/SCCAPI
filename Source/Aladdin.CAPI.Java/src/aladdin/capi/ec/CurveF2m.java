package aladdin.capi.ec;
import aladdin.math.*;
import java.security.spec.*; 
import java.math.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////
// Эллиптическая кривая над полем F2m
////////////////////////////////////////////////////////////////////////////
public class CurveF2m extends Curve
{
    private static final long serialVersionUID = -1687595551416292398L;
    
    // эллиптическая кривая
    private final aladdin.math.F2m.EllipticCurve ec; 
    
    // преобразовать тип кривой
    public static CurveF2m convert(java.security.spec.EllipticCurve curve)
    {
        // проверить тип кривой
        if (curve instanceof CurveF2m) return (CurveF2m)curve; 
        
        // извлечь используемое поле
        ECField ecField = curve.getField(); if (!(ecField instanceof ECFieldF2m))
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // выполнить преобразование поля
        FieldF2m field = FieldF2m.convert((ECFieldF2m)ecField); 
                    
        // указать эллиптическую кривую
        return new CurveF2m(field, curve.getA(), curve.getB(), curve.getSeed()); 
    }
    // конструктор
    public CurveF2m(aladdin.math.F2m.EllipticCurve ec, byte[] seed) 
    {  
        // сохранить переданные параметры
        super(FieldF2m.convert(ec.field()), ec.a().toBigInteger(), ec.b().toBigInteger(), seed); this.ec = ec;
    } 
    // конструктор
    public CurveF2m(FieldF2m field, BigInteger a, BigInteger b, byte[] seed) 
    { 
        // сохранить переданные параметры
        super(field, a, b, seed); int m = field.getM(); 
            
        // проверить корректность параметров
        if (a.bitLength() > m || b.bitLength() > m) throw new IllegalArgumentException();

        // преобразовать тип коэффициентов
        Vector vectorA = new Vector(a, m); Vector vectorB = new Vector(b, m); 

        // в зависимости от типа поля
        if (field.getReductionPolynomial() == null)
        {
            // указать используемой поле
            aladdin.math.F2m.Field mathField = new aladdin.math.F2m.NormField(m); 

            // создать эллиптическую кривую
            ec = new aladdin.math.F2m.EllipticCurve(mathField, vectorA, vectorB);
        }
        else {
            // преобразовать тип образующего многочлена
            Polynom polynom = new Polynom(field.getReductionPolynomial()); 

            // указать используемой поле
            aladdin.math.F2m.Field mathField = new aladdin.math.F2m.PolyField(polynom); 

            // создать эллиптическую кривую
            ec = new aladdin.math.F2m.EllipticCurve(mathField, vectorA, vectorB);
        }
    } 
    ///////////////////////////////////////////////////////////////////////
    // Свойства эллиптической кривой
    ///////////////////////////////////////////////////////////////////////
    
    // конечное поле
    @Override public final FieldF2m getField() { return (FieldF2m)super.getField(); }
    
    // признак принадлежности эллиптической кривой
    @Override public final boolean isPoint(ECPoint P)
    {
        // извлечь математическую точку
        aladdin.math.Point<Vector> mathPoint = getMathPoint(P); 
        
        // проверить принадлежность точки
        return ec.isPoint(mathPoint); 
    }
    // создать точку на эллиптической кривой
    @Override protected ECPoint createPoint(
        BigInteger x, BigInteger y) throws IOException
    {
        // создать точку на эллиптической кривой
        aladdin.math.Point<Vector> mathPoint = 
            new aladdin.math.Point<Vector>(
                new Vector(x, getField().getM()), 
                new Vector(y, getField().getM()) 
        ); 
        // проверить принадлежность точки
        if (!ec.isPoint(mathPoint)) throw new IOException(); 
        
        // вернуть созданную точку
        return new Point<Vector>(mathPoint, x, y); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Операции аддитивной группы
    ///////////////////////////////////////////////////////////////////////////
    @Override public final ECPoint negate(ECPoint P)
    {
        // извлечь математическую точку
        aladdin.math.Point<Vector> mathPoint = getMathPoint(P); 
        
        // вычислить противоположную точку
        mathPoint = ec.negate(mathPoint); 
        
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<Vector>(mathPoint, 
            mathPoint.x().toBigInteger(), mathPoint.y().toBigInteger()
        ); 
    }
    @Override public final ECPoint add(ECPoint P, ECPoint Q)
    {
        // извлечь математические точки
        aladdin.math.Point<Vector> mathPointP = getMathPoint(P); 
        aladdin.math.Point<Vector> mathPointQ = getMathPoint(Q); 
        
        // вычислить сумму точек
        aladdin.math.Point<Vector> mathPoint = ec.add(
            mathPointP, mathPointQ
        ); 
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<Vector>(mathPoint, 
            mathPoint.x().toBigInteger(), mathPoint.y().toBigInteger()
        ); 
    }
    @Override public final ECPoint subtract(ECPoint P, ECPoint Q)
    {
        // извлечь математические точки
        aladdin.math.Point<Vector> mathPointP = getMathPoint(P); 
        aladdin.math.Point<Vector> mathPointQ = getMathPoint(Q); 
        
        // вычислить разность точек
        aladdin.math.Point<Vector> mathPoint = ec.subtract(
            mathPointP, mathPointQ
        ); 
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<Vector>(mathPoint, 
            mathPoint.x().toBigInteger(), mathPoint.y().toBigInteger()
        ); 
    }
    @Override public final ECPoint twice(ECPoint P)
    {
        // извлечь математическую точку
        aladdin.math.Point<Vector> mathPoint = getMathPoint(P); 
        
        // вычислить удвоенную точку
        mathPoint = ec.twice(mathPoint); 

        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<Vector>(mathPoint, 
            mathPoint.x().toBigInteger(), mathPoint.y().toBigInteger()
        ); 
    }
    // вычисление кратного элемента
    @Override public final ECPoint multiply(ECPoint P, BigInteger e)
    {
        // извлечь математическую точку
        aladdin.math.Point<Vector> mathPoint = getMathPoint(P); 
        
        // вычислить кратный элемент
        mathPoint = ec.multiply(mathPoint, e); 

        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<Vector>(mathPoint, 
            mathPoint.x().toBigInteger(), mathPoint.y().toBigInteger()
        ); 
    }
    // сумма кратных элементов
    @Override public final ECPoint multiply_sum(
        ECPoint P, BigInteger a, ECPoint Q, BigInteger b)
    {
        // извлечь математические точки
        aladdin.math.Point<Vector> mathPointP = getMathPoint(P); 
        aladdin.math.Point<Vector> mathPointQ = getMathPoint(Q); 
        
        // вычислить сумму кратных элементов
        aladdin.math.Point<Vector> mathPoint = ec.multiply_sum(
            mathPointP, a, mathPointQ, b
        ); 
        // проверить на бесконечную точку
        if (ec.isZero(mathPoint)) return zero(); 
        
        // вернуть результат
        return new Point<Vector>(mathPoint, 
            mathPoint.x().toBigInteger(), mathPoint.y().toBigInteger()
        ); 
    }
    // извлечь математическую точку
    @SuppressWarnings({"unchecked"}) 
    private aladdin.math.Point<Vector> getMathPoint(ECPoint P)
    {
        // проверить на бесконечную точку
        if (isZero(P)) return ec.zero(); 
        
        // выполнить преобразование типа
        if (P instanceof Point) return ((Point<Vector>)P).mathPoint(); 
        
        // создать математическую точку
        return new aladdin.math.Point<Vector>(
            new Vector(P.getAffineX(), getField().getM()), 
            new Vector(P.getAffineY(), getField().getM()) 
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование точек эллиптической кривой
    ///////////////////////////////////////////////////////////////////////////
    
    // вычислить дополнительный бит при сжатии
    @Override protected int compress(ECPoint P)
    {
        // извлечь математическую точку
        aladdin.math.Point<Vector> mathPoint = getMathPoint(P); 
        
        // вычислить дополнительный бит при сжатии
        return ec.compress(mathPoint); 
    }
    // вычислить точку кривой при расжатии
    @Override protected ECPoint decompress(BigInteger x, int y0) throws IOException
    {
        // выполнить преобразование типа
        Vector vectorX = new Vector(x, getField().getFieldSize()); 
        try { 
            // вычислить точку кривой при расжатии
            aladdin.math.Point<Vector> mathPoint = ec.decompress(vectorX, y0); 

            // проверить на бесконечную точку
            if (ec.isZero(mathPoint)) return zero(); 
        
            // выполнить преобразование типа
            return new Point<Vector>(mathPoint, 
                mathPoint.x().toBigInteger(), mathPoint.y().toBigInteger()
            ); 
        }
        // обработать возможное исключение
        catch (ArithmeticException e) { throw new IOException(e); }
    }
}
