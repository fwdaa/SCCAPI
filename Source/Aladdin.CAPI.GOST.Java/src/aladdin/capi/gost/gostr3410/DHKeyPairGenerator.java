package aladdin.capi.gost.gostr3410;
import aladdin.capi.*; 
import java.math.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////
public class DHKeyPairGenerator extends aladdin.capi.software.KeyPairGenerator
{
    // параметры ключей
	private final IDHParameters	parameters;

	// конструктор
	public DHKeyPairGenerator(Factory factory, 
        SecurityObject scope, IRand rand, IDHParameters parameters)
    {  
        // сохранить переданные параметры
		super(factory, scope, rand); this.parameters = parameters;
    }
	@Override public KeyPair generate(String keyOID) throws IOException  
	{
        // получить фабрику кодирования
        aladdin.capi.KeyFactory keyFactory = factory().getKeyFactory(keyOID); 
        
		// получить параметры алгоритма
		BigInteger p = parameters.getP(); BigInteger q = parameters.getQ();
        
		// указать начальные условия
        BigInteger x = BigInteger.ZERO; int bitsQ = q.bitLength();
        
        // указать генератор случайных чисел
        try (Random random = new Random(rand())) 
        {
            // проверить выполнение требуемых условий
            while (x.signum() == 0 || x.compareTo(q) >= 0)
            {
                // сгенерировать случайное число
                x = new BigInteger(bitsQ, random);
            }
        }
		// умножить базовую точку на число
		BigInteger y = parameters.getG().modPow(x, p); 

		// создать открытый ключ
		IDHPublicKey publicKey = new DHPublicKey(keyFactory, parameters, y);
        
        // создать личный ключ
		try (IDHPrivateKey privateKey = new DHPrivateKey(
            factory(), scope(), keyOID, parameters, x))
        {
            // вернуть созданную пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
	}
}
