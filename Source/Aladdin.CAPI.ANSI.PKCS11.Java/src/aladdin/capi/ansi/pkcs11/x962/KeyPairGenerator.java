package aladdin.capi.ansi.pkcs11.x962;
import aladdin.pkcs11.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей EC/ECDSA
///////////////////////////////////////////////////////////////////////////
public class KeyPairGenerator extends aladdin.capi.pkcs11.KeyPairGenerator
{
	// параметры генерации
	private final aladdin.capi.ansi.x962.Parameters parameters; 
    // информация алгоритма
    private final MechanismInfo info; 

	// конструктор
	public KeyPairGenerator(Applet applet, SecurityObject scope, 
        IRand rand, aladdin.capi.ansi.x962.Parameters parameters) throws IOException
	{
		// сохранить переданные параметры
		super(applet, scope, rand); this.parameters = parameters; 

        // получить информацию механизма
        info = applet().getAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 
    }
	// сгенерировать пару ключей
    @Override
	public KeyPair generate(String keyOID, KeyUsage keyUsage) throws IOException
    {
        // указать программный алгоритм генерации
        try (aladdin.capi.KeyPairGenerator generator = 
            new aladdin.capi.ansi.x962.KeyPairGenerator(
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
		return new Mechanism(API.CKM_EC_KEY_PAIR_GEN); 
	}
	// атрибуты открытого ключа
    @Override protected Attribute[] getPublicAttributes(String keyOID)
    { 
        // создать атрибут параметров
        Attribute parametersAttribute = PublicKey.getParametersAttribute(
            parameters, info.flags()
        ); 
        // вернуть атрибут параметров
        return new Attribute[] { parametersAttribute }; 
    } 
}
