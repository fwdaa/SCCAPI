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
} 
