package aladdin.capi.ansi.rsa;
import java.math.*; 
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры RSA
///////////////////////////////////////////////////////////////////////////////
public class Parameters extends RSAKeyGenParameterSpec implements IParameters
{
    // конструктор
    public Parameters(int modulusBits, BigInteger publicExponent) 
    { 
        // сохранить переданные параметры
        super(modulusBits, publicExponent != null ? publicExponent : BigInteger.valueOf(0x10001L)); 
        
        // проверить размер модуля в битах
		if (384 > modulusBits || modulusBits > 16384) throw new IllegalArgumentException();
    } 
    // размер модуля в битах
    @Override public int getModulusBits() { return getKeysize(); }
} 
