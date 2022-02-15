package aladdin.capi.ansi.pkcs11.x957;
import aladdin.math.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей DSA
///////////////////////////////////////////////////////////////////////////
public class KeyPairGenerator extends aladdin.capi.pkcs11.KeyPairGenerator
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	// параметры генерации
	private final aladdin.capi.ansi.x957.IParameters parameters; 

	// конструктор
	public KeyPairGenerator(Applet applet, SecurityObject scope, 
        aladdin.capi.ansi.x957.IParameters parameters, IRand rand)
	{
		// сохранить переданные параметры
		super(applet, scope, rand); this.parameters = parameters; 
	}
	// сгенерировать пару ключей
    @Override
	public KeyPair generate(String keyOID, KeyUsage keyUsage) throws IOException
    {
        // указать программный алгоритм генерации
        try (aladdin.capi.KeyPairGenerator generator = 
            new aladdin.capi.ansi.x957.KeyPairGenerator(
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
		return new Mechanism(API.CKM_DSA_KEY_PAIR_GEN); 
	}
	// атрибуты открытого ключа
    @Override protected Attribute[] getPublicAttributes(String keyOID) 
    { 
        // создать список атрибутов
        return new Attribute[] { 
            new Attribute(API.CKA_PRIME,    Convert.fromBigInteger(parameters.getP(), ENDIAN)), 
            new Attribute(API.CKA_SUBPRIME, Convert.fromBigInteger(parameters.getQ(), ENDIAN)),  
            new Attribute(API.CKA_BASE ,    Convert.fromBigInteger(parameters.getG(), ENDIAN)) 
        }; 
    } 
}
