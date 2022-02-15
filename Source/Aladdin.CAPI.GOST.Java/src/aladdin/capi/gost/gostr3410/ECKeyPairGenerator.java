package aladdin.capi.gost.gostr3410;
import aladdin.capi.*; 
import aladdin.capi.ec.*; 
import java.security.spec.*; 
import java.math.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей ГОСТ Р 34.10-2001,2012
///////////////////////////////////////////////////////////////////////
public class ECKeyPairGenerator extends aladdin.capi.software.KeyPairGenerator
{
    // параметры ключей
	private final IECParameters parameters;

	// конструктор
	public ECKeyPairGenerator(Factory factory, 
        SecurityObject scope, IRand rand, IECParameters parameters)
    {
        // сохранить переданные параметры
		super(factory, scope, rand); this.parameters = parameters;
    }
	@Override public KeyPair generate(String keyOID) throws IOException   
	{
        // получить фабрику кодирования
        aladdin.capi.KeyFactory keyFactory = factory().getKeyFactory(keyOID); 
        
		// получить параметры алгоритма
		Curve ec = parameters.getCurve(); BigInteger d = BigInteger.ZERO; 
        
		// получить параметры алгоритма
        BigInteger n = parameters.getOrder(); int bitsN = n.bitLength(); 
        
        // указать генератор случайных чисел
        try (Random random = new Random(rand())) 
        {
            // проверить выполнение требуемых условий
            while (d.signum() == 0 || d.compareTo(n) >= 0)
            {
                // сгенерировать случайное число
                d = new BigInteger(bitsN, random);
            }
        }
		// умножить базовую точку на число
		ECPoint Q = ec.multiply(parameters.getGenerator(), d); 

		// создать открытый ключ
		IECPublicKey publicKey = new ECPublicKey(keyFactory, parameters, Q);
        
        // создать личный ключ
		try (IECPrivateKey privateKey = new ECPrivateKey(
            factory(), scope(), keyOID, parameters, d))
        {
            // вернуть созданную пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
	}
}
