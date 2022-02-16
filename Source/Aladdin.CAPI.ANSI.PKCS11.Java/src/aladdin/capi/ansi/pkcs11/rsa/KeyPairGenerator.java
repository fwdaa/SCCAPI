package aladdin.capi.ansi.pkcs11.rsa;
import aladdin.math.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей RSA
///////////////////////////////////////////////////////////////////////////
public class KeyPairGenerator extends aladdin.capi.pkcs11.KeyPairGenerator
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	// параметры генерации
	private final aladdin.capi.ansi.rsa.IParameters parameters; private final long algID; 

	// конструктор
	public KeyPairGenerator(Applet applet, SecurityObject scope, 
        IRand rand, aladdin.capi.ansi.rsa.IParameters parameters, long algID)
	{
		// сохранить переданные параметры
		super(applet, scope, rand); this.parameters = parameters; this.algID = algID; 
	}
	// сгенерировать пару ключей
    @Override
	public KeyPair generate(String keyOID, KeyUsage keyUsage) throws IOException
    {
        // указать программный алгоритм генерации
        try (aladdin.capi.KeyPairGenerator generator = 
            new aladdin.capi.ansi.rsa.KeyPairGenerator(
                factory(), scope(), rand(), parameters))
        { 
            // сгенерировать пару ключей
            return generator.generate(null, keyOID, keyUsage, KeyFlags.NONE);  
        }
    }
	// параметры алгоритма
    @Override protected Mechanism getParameters(Session sesssion, String keyOID)
	{
		// вернуть параметры алгоритма
		return new Mechanism(algID); 
	}
	// атрибуты открытого ключа
    @Override protected Attribute[] getPublicAttributes(String keyOID) 
    { 
        // закодировать параметры генерации
        byte[] publicExponent = Convert.fromBigInteger(parameters.getPublicExponent(), ENDIAN);
        
        // создать список атрибутов
        return new Attribute[] { 

            // указать размер модуля в битах
            new Attribute(API.CKA_MODULUS_BITS, parameters.getModulusBits()), 
            
            // указать размер величину экспоненты
            new Attribute(API.CKA_PUBLIC_EXPONENT, publicExponent)    
        }; 
    } 
}
