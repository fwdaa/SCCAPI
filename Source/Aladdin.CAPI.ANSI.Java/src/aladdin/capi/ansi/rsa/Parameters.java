package aladdin.capi.ansi.rsa;
import aladdin.capi.*; 
import java.math.*; 
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры RSA
///////////////////////////////////////////////////////////////////////////////
public class Parameters extends RSAKeyGenParameterSpec implements IParameters
{
    private static final long serialVersionUID = -5761537522124512722L;
    
    // преобразовать параметры алгоритма
    public static IParameters convert(aladdin.capi.IParameters parameters)
    {
        // при полном указании параметров преобразовать тип параметров
        if (parameters instanceof IParameters) return (IParameters)parameters;
    
        // указать параметры алгоритма
        return new Parameters((IKeyBitsParameters)parameters); 
    }
    // конструктор
    public static IParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // в зависимости от типа данных
        if (paramSpec instanceof RSAKeyGenParameterSpec)
        {
            // выполнить преобразование типа
            if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
            
            // выполнить преобразование типа
            RSAKeyGenParameterSpec rsaParamSpec = (RSAKeyGenParameterSpec)paramSpec; 
            
            // создать параметры ключа
            return new Parameters(rsaParamSpec.getKeysize(), 
                rsaParamSpec.getPublicExponent()
            ); 
        }
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
    // конструктор
    public Parameters(int modulusBits, BigInteger publicExponent) 
    { 
        // сохранить переданные параметры
        super(modulusBits, publicExponent); 
        
        // проверить размер модуля в битах
		if (384 > modulusBits || modulusBits > 16384) throw new IllegalArgumentException();
    } 
    // конструктор
    public Parameters(int modulusBits) 
    { 
        // сохранить переданные параметры
        super(modulusBits, BigInteger.valueOf(0x10001L)); 
        
        // проверить размер модуля в битах
		if (384 > modulusBits || modulusBits > 16384) throw new IllegalArgumentException();
    } 
    // конструктор
    public Parameters(IKeyBitsParameters parameters) { this(parameters.getKeyBits()); }
        
    // размер ключа в битах
    @Override public int getKeyBits() { return getKeysize(); }
    // размер модуля в битах
    @Override public int getModulusBits() { return getKeysize(); }

    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(RSAKeyGenParameterSpec.class)) return (T)this; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    } 
} 
