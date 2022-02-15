package aladdin.capi.ansi.kea;
import aladdin.capi.*; 
import java.math.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей KEA
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

		// определить параметры алгоритма
		BigInteger P = parameters.getP(); BigInteger Q = parameters.getQ();
		BigInteger G = parameters.getG(); BigInteger X; 

        // указать генератор случайных чисел
        try (Random random = new Random(rand())) 
        {
            // вычислить предел генерации
            BigInteger max = Q.subtract(BigInteger.valueOf(2)); 

			// сгенерировать случайное число
            int N = Q.bitLength(); do { X = new BigInteger(N, random); }
            
            // проверить условие генерации
            while (X.compareTo(max) >= 0); X = X.add(BigInteger.ONE); 
        }
		// вычислить открытый ключ
		BigInteger Y = G.modPow(X, P);
        
		// создать открытый ключ и личный ключ 
		IPublicKey publicKey = new PublicKey(keyFactory, parameters, Y); 
        
		// создать личный ключ 
		try (IPrivateKey privateKey = new PrivateKey(
            factory(), scope(), keyOID, parameters, X))
        {
            // вернуть созданную пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
	}
}
