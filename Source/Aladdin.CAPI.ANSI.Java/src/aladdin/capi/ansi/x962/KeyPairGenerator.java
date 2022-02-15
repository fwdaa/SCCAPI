package aladdin.capi.ansi.x962;
import aladdin.capi.*;
import aladdin.capi.ec.*; 
import java.security.spec.*; 
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей 
///////////////////////////////////////////////////////////////////////////
public class KeyPairGenerator extends aladdin.capi.software.KeyPairGenerator
{
    // параметры ключей
	private final IParameters parameters;

	// конструктор
	public KeyPairGenerator(Factory factory, 
        SecurityObject scope, IRand rand, IParameters parameters)
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
        
        // указать генератор случайных данных
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
		IPublicKey publicKey = new PublicKey(keyFactory, parameters, Q);
        
		// создать личный ключ
		try (IPrivateKey privateKey = new PrivateKey(
            factory(), scope(), keyOID, parameters, d))
        {
            // вернуть созданную пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
	}
}
