package aladdin.capi.stb.stb11762;
import aladdin.math.Fp.*; 
import aladdin.capi.*; 
import java.io.*;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей подписи СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDSKeyPairGenerator extends aladdin.capi.software.KeyPairGenerator
{
    // параметры ключей
	private final IBDSParameters parameters;

	// конструктор
	public BDSKeyPairGenerator(Factory factory, 
        SecurityObject scope, IRand rand, IBDSParameters parameters)
    { 
        // сохранить переданные параметры
		super(factory, scope, rand); this.parameters = parameters;
    }
	@Override public KeyPair generate(String keyOID) throws IOException   
	{
        // получить фабрику кодирования
        aladdin.capi.KeyFactory keyFactory = factory().getKeyFactory(keyOID); 
        
		// определить параметры алгоритма
		BigInteger P = parameters.bdsP(); BigInteger Q = parameters.bdsQ();
		BigInteger A = parameters.bdsA(); BigInteger X; 

        // указать генератор случайных чисел
        try (Random random = new Random(rand())) 
        {
            // сгенерировать случайное число X
            do { X = new BigInteger(parameters.bdsR(), random); }

            // проверить выполнение требуемых условий
            while (X.signum() == 0 || X.compareTo(Q) >= 0);
        }
		// вычислить открытый ключ
		BigInteger Y = (new MontGroup(P)).power(A, X);

		// создать открытый ключ
		IPublicKey publicKey = new BDSPublicKey(keyFactory, parameters, Y); 

		// создать открытый ключ и личный ключ 
        try (IPrivateKey privateKey = new BDSPrivateKey(
            factory(), scope(), keyOID, parameters, X))
        {
            // вернуть созданную пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
	}
}
