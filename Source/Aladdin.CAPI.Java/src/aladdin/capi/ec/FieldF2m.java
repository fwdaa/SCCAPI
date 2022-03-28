package aladdin.capi.ec;
import aladdin.math.*; 
import java.security.spec.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Поле многочленов (F_{2^m})
///////////////////////////////////////////////////////////////////////////
public class FieldF2m extends ECFieldF2m implements IField<BigInteger>
{
    private static final long serialVersionUID = -6167456552875200424L;
    
    // математическое поле
    private final aladdin.math.F2m.Field field; 
    
    // преобразовать тип поля
    @SuppressWarnings({"rawtypes"}) 
    public static FieldF2m convert(aladdin.math.F2m.Field field)
    {
        // в зависимости от типа поля
        if (field instanceof aladdin.math.F2m.PolyField)
        {
            // выполнить преобразование типа
            return new FieldF2m((aladdin.math.F2m.PolyField)field); 
        }
        // выполнить преобразование типа
        else return new FieldF2m((aladdin.math.F2m.NormField)field); 
    }
    // преобразовать тип поля
    public static FieldF2m convert(ECFieldF2m field)
    {
        // проверить тип поля
        if (field instanceof FieldF2m) return (FieldF2m)field;
        
        // получить образующий многочлен
        BigInteger polynom = field.getReductionPolynomial(); 
        
        // создать требуемое поле
        if (polynom == null) return new FieldF2m(field.getM());
        
        // создать требуемое поле
        else return new FieldF2m(field.getM(), polynom); 
    }
    // конструктор
    public FieldF2m(aladdin.math.F2m.PolyField field) 
    {
        // сохранить переданные параметры
        super(field.m(), field.polynom().toBigInteger()); this.field = field; 
    }
    // конструктор
    public FieldF2m(aladdin.math.F2m.NormField field) 
    {
        // сохранить переданные параметры
        super(field.m()); this.field = field; 
    }
    // конструктор
    public FieldF2m(int m, BigInteger polynom) 
    {
        // сохранить переданные параметры
        super(m, polynom); field = new aladdin.math.F2m.PolyField(new Polynom(polynom)); 
    }
    // конструктор
    public FieldF2m(int m) 
    {
        // сохранить переданные параметры
        super(m); field = new aladdin.math.F2m.NormField(m); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Операции аддитивной группы
    ///////////////////////////////////////////////////////////////////////////

    // признак нулевого элемента
    @Override public boolean isZero(BigInteger P) { return P.signum() == 0; }
    // нулевой элемент
    @Override public BigInteger zero() { return BigInteger.ZERO; }
    
    // противоположный элемент
    @Override public BigInteger negate(BigInteger P) 
    { 
        // выполнить преобразование типа
        Vector element = new Vector(P, getM()); 
        
        // вычислить противоположный элемент
        return field.negate(element).toBigInteger(); 
    } 
    // удвоенный элемент
    @Override public BigInteger twice(BigInteger P) 
    { 
        // выполнить преобразование типа
        Vector element = new Vector(P, getM()); 
        
        // вычислить удвоенный элемент
        return field.twice(element).toBigInteger(); 
    } 
    // сложение элементов
    @Override public BigInteger add(BigInteger P, BigInteger Q)
    {
        // выполнить преобразование типа
        Vector elementP = new Vector(P, getM()); 
        Vector elementQ = new Vector(Q, getM()); 
        
        // выполнить сложение элементов
        return field.add(elementP, elementQ).toBigInteger(); 
    }
    // вычитание элементов
    @Override public BigInteger subtract(BigInteger P, BigInteger Q)
    {
        // выполнить преобразование типа
        Vector elementP = new Vector(P, getM()); 
        Vector elementQ = new Vector(Q, getM()); 
        
        // выполнить вычитание элементов
        return field.subtract(elementP, elementQ).toBigInteger(); 
    }
    // вычисление кратного элемента
    @Override public BigInteger multiply(BigInteger P, BigInteger e)
    {
        // выполнить преобразование типа
        Vector element = new Vector(P, getM()); 
        
        // вычислить кратный элемент
        return field.multiply(element, e).toBigInteger(); 
    }
    // сумма кратных элементов
    @Override public BigInteger multiply_sum(
        BigInteger P, BigInteger a, BigInteger Q, BigInteger b)
    {
        // выполнить преобразование типа
        Vector elementP = new Vector(P, getM()); 
        Vector elementQ = new Vector(Q, getM()); 
        
        // вычислить сумму кратных элементов
        return field.multiply_sum(elementP, a, elementQ, b).toBigInteger(); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Операции мультипликативной группы
    ///////////////////////////////////////////////////////////////////////////
    
    // признак единичного элемента
    @Override public boolean isOne(BigInteger P) 
    { 
        // признак единичного элемента
        return field.isOne(new Vector(P, getM())); 
    } 
    // единичный элемент
    @Override public BigInteger one() { return field.one().toBigInteger(); }
    
    // обратный элемент
    @Override public BigInteger invert(BigInteger P) 
    { 
        // выполнить преобразование типа
        Vector element = new Vector(P, getM()); 
        
        // вычислить обратный элемент
        return field.invert(element).toBigInteger(); 
    } 
    // возведенный в квадрат элемент
    @Override public BigInteger sqr(BigInteger P) 
    { 
        // выполнить преобразование типа
        Vector element = new Vector(P, getM()); 
        
        // вычислить возведенный в квадрат элемент
        return field.sqr(element).toBigInteger(); 
    } 
    // умножение элементов
    @Override public BigInteger product(BigInteger P, BigInteger Q)
    {
        // выполнить преобразование типа
        Vector elementP = new Vector(P, getM()); 
        Vector elementQ = new Vector(Q, getM()); 
        
        // выполнить умножение элементов
        return field.product(elementP, elementQ).toBigInteger(); 
    }
    // деление элементов
    @Override public BigInteger divide(BigInteger P, BigInteger Q)
    {
        // выполнить преобразование типа
        Vector elementP = new Vector(P, getM()); 
        Vector elementQ = new Vector(Q, getM()); 
        
        // выполнить деление элементов
        return field.divide(elementP, elementQ).toBigInteger(); 
    }
    // возведение в степень элемента
    @Override public BigInteger power(BigInteger P, BigInteger e)
    {
        // выполнить преобразование типа
        Vector element = new Vector(P, getM()); 
        
        // выполнить возведение в степень
        return field.power(element, e).toBigInteger(); 
    }
    // умножение возведенных в степень элементов
    @Override public BigInteger power_product(
        BigInteger P, BigInteger a, BigInteger Q, BigInteger b)
    {
        // выполнить преобразование типа
        Vector elementP = new Vector(P, getM()); 
        Vector elementQ = new Vector(Q, getM()); 
        
        // выполнить умножение возведенных в степень элементов
        return field.power_product(elementP, a, elementQ, b).toBigInteger(); 
    }
}
