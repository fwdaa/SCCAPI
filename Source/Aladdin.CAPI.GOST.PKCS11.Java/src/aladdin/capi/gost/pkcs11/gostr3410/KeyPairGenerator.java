package aladdin.capi.gost.pkcs11.gostr3410;
import aladdin.asn1.*; 
import aladdin.capi.*; 
import aladdin.capi.gost.gostr3410.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей ГОСТ R 34.10-2001
///////////////////////////////////////////////////////////////////////////
public class KeyPairGenerator extends aladdin.capi.pkcs11.KeyPairGenerator
{
	// параметры генерации
	private final aladdin.capi.gost.gostr3410.INamedParameters parameters; 

	// конструктор
	public KeyPairGenerator(Applet applet, SecurityObject scope, 
        IRand rand, aladdin.capi.gost.gostr3410.INamedParameters parameters)
	{
		// создать список атрибутов
		super(applet, scope, rand); this.parameters = parameters; 
	}
	// сгенерировать пару ключей
    @Override
	public KeyPair generate(String keyOID, KeyUsage keyUsage) throws IOException
    {
        // указать программный алгоритм генерации
        try (aladdin.capi.KeyPairGenerator generator = new ECKeyPairGenerator(
            factory(), scope(), rand(), (IECParameters)parameters))
        { 
            // сгенерировать пару ключей
            return generator.generate(null, keyOID, keyUsage, KeyFlags.NONE);  
        }
    }
	// параметры алгоритма
    @Override protected Mechanism getParameters(Session sesssion, String keyOID)
	{
		// в зависимости от идентификатора ключа
		if (!keyOID.equals(aladdin.asn1.gost.OID.GOSTR3410_2012_512))
		{
			// вернуть параметры алгоритма
			return new Mechanism(API.CKM_GOSTR3410_KEY_PAIR_GEN); 
		}
		// вернуть параметры алгоритма
		else return new Mechanism(API.CKM_GOSTR3410_512_KEY_PAIR_GEN); 
	}
	// атрибуты открытого ключа
    @Override protected Attribute[] getPublicAttributes(String keyOID) 
    { 
        // создать список атрибутов
        List<Attribute> attributes = new ArrayList<Attribute>(); 

        // указать идентификатор набора
        attributes.add(new Attribute(API.CKA_GOSTR3410_PARAMS, 
            new ObjectIdentifier(parameters.paramOID()).encoded()
        ));   
        // в зависимости от идентификатора ключа
        if (!keyOID.equals(aladdin.asn1.gost.OID.GOSTR3410_2012_512))
        {
            // указать идентификатор набора
            attributes.add(new Attribute(API.CKA_GOSTR3411_PARAMS, 
                new ObjectIdentifier(parameters.hashOID()).encoded()
            ));   
            // указать идентификатор набора
            attributes.add(new Attribute(API.CKA_GOST28147_PARAMS, 
                new ObjectIdentifier(parameters.sboxOID()).encoded()
            ));   
        }
        // создать список атрибутов
        return attributes.toArray(new Attribute[attributes.size()]);  
    } 
}
