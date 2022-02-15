package aladdin.capi.stb.stb34101;
import aladdin.capi.*;
import aladdin.capi.ec.*;
import java.io.*;
import java.security.spec.*; 
import java.math.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации двойных ключей СТБ 34.101
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
		Curve ec = parameters.getCurve(); BigInteger q = parameters.getOrder();

		// создать базовую точку эллиптической кривой
		ECPoint G = parameters.getGenerator(); 
			
        // указать начальные условия
		BigInteger d = BigInteger.ZERO; int bitsQ = q.bitLength();

        // указать генератор случайных чисел
        try (Random random = new Random(rand())) 
        {
            // проверить выполнение требуемых условий
            while (d.signum() == 0 || d.compareTo(q) >= 0)
            {
                // сгенерировать случайное число
                d = new BigInteger(bitsQ, random);
            }
        }
		// умножить базовую точку на число
		ECPoint Q = ec.multiply(G, d); 

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