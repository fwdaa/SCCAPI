package aladdin.capi.ec;
import aladdin.math.*; 
import java.security.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Поле по простому модулю (Fp)
///////////////////////////////////////////////////////////////////////////
public class FieldFp extends ECFieldFp implements IField<BigInteger>
{
    private static final long serialVersionUID = -7786251191037833551L;
    
    // математическое поле
    private final aladdin.math.Fp.Field field; 
    
    // преобразовать тип поля
    public static FieldFp convert(ECFieldFp field)
    {
        // проверить тип поля
        if (field instanceof FieldFp) return (FieldFp)field; 
        
        // создать поле
        return new FieldFp(field.getP()); 
    }
    // конструктор
    public FieldFp(aladdin.math.Fp.Field field) 
    {
        // сохранить переданные параметры
        super(field.p()); this.field = field; 
    }
    // конструктор
    public FieldFp(BigInteger p) 
    {
        // сохранить переданные параметры
        super(p); field = new aladdin.math.Fp.Field(p); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Операции аддитивной группы
    ///////////////////////////////////////////////////////////////////////////

    // признак нулевого элемента
    @Override public boolean isZero(BigInteger P) { return P.signum() == 0; }
    // нулевой элемент
    @Override public BigInteger zero() { return BigInteger.ZERO; }
    
    // противоположный и удвоенный элемент
    @Override public BigInteger negate(BigInteger P) { return field.negate(P); } 
    @Override public BigInteger twice (BigInteger P) { return field.twice (P); } 
    
    // сложение элементов
    @Override public BigInteger add(BigInteger P, BigInteger Q)
    {
        // выполнить сложение элементов
        return field.add(P, Q); 
    }
    // вычитание элементов
    @Override public BigInteger subtract(BigInteger P, BigInteger Q)
    {
        // выполнить вычитание элементов
        return field.subtract(P, Q); 
    }
    // вычисление кратного элемента
    @Override public BigInteger multiply(BigInteger P, BigInteger e)
    {
        // вычислить кратный элемент
        return field.multiply(P, e); 
    }
    // сумма кратных элементов
    @Override public BigInteger multiply_sum(
        BigInteger P, BigInteger a, BigInteger Q, BigInteger b)
    {
        // вычислить сумму кратных элементов
        return field.multiply_sum(P, a, Q, b); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Операции мультипликативной группы
    ///////////////////////////////////////////////////////////////////////////
    
    // признак единичного элемента
    @Override public boolean isOne(BigInteger P) { return field.isOne(P); } 
    // единичный элемент
    @Override public BigInteger one() { return BigInteger.ONE; }
    
    // обратный и возведенный в квадрат элемент
    @Override public BigInteger invert(BigInteger P) { return field.invert(P); } 
    @Override public BigInteger sqr   (BigInteger P) { return field.sqr   (P); } 
    
    // умножение элементов
    @Override public BigInteger product(BigInteger P, BigInteger Q)
    {
        // выполнить умножение элементов
        return field.product(P, Q); 
    }
    // деление элементов
    @Override public BigInteger divide(BigInteger P, BigInteger Q)
    {
        // вычислить деление элементов
        return field.divide(P, Q); 
    }
    // возведение в степень элемента
    @Override public BigInteger power(BigInteger P, BigInteger e)
    {
        // выполнить возведение в степень
        return field.power(P, e); 
    }
    // умножение возведенных в степень элементов
    @Override public BigInteger power_product(
        BigInteger P, BigInteger a, BigInteger Q, BigInteger b)
    {
        // выполнить умножение возведенных в степень элементов
        return field.power_product(P, a, Q, b); 
    }
}
