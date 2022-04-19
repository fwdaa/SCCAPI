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
        return new Parameters(((IKeySizeParameters)parameters).getKeyBits()); 
    }
    // конструктор
    public static IParameters getInstance(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException
    { 
        // выполнить преобразование типа
        if (paramSpec instanceof IParameters) return (IParameters)paramSpec; 
            
        // в зависимости от типа данных
        if (paramSpec instanceof RSAKeyGenParameterSpec)
        {
            // выполнить преобразование типа
            RSAKeyGenParameterSpec rsaParamSpec = (RSAKeyGenParameterSpec)paramSpec; 
            
            // создать параметры ключа
            return new Parameters(
                rsaParamSpec.getKeysize(), rsaParamSpec.getPublicExponent()
            ); 
        }
        // в зависимости от типа данных
        if (paramSpec instanceof KeySizeParameterSpec)
        {
            // выполнить преобразование типа
            KeySizeParameterSpec keySizeParamSpec = (KeySizeParameterSpec)paramSpec; 

            // создать параметры ключа
            return new Parameters(keySizeParamSpec.getKeyBits()); 
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
    // размер модуля в битах
    @Override public int getKeyBits    () { return getKeysize(); }
    @Override public int getModulusBits() { return getKeysize(); }

    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // вернуть параметры
        if (specType.isAssignableFrom(IParameters.class)) return (T)this; 
        
        // вернуть параметры
        if (specType.isAssignableFrom(RSAKeyGenParameterSpec.class)) return (T)this; 
        
        // в зависимости от типа
        if (specType.isAssignableFrom(KeySizeParameterSpec.class)) 
        {
            // вернуть параметры
            return (T)new KeySizeParameterSpec(getKeysize()); 
        }
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    } 
} 
