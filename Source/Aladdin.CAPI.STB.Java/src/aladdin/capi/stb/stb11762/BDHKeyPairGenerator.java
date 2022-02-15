package aladdin.capi.stb.stb11762;
import aladdin.math.Fp.*;
import aladdin.capi.*; 
import java.io.*;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей обмена СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDHKeyPairGenerator extends aladdin.capi.software.KeyPairGenerator
{
    // параметры ключей
	private final IBDHParameters parameters;

	// конструктор
	public BDHKeyPairGenerator(Factory factory, 
        SecurityObject scope, IRand rand, IBDHParameters parameters) 
    { 
        // сохранить переданные параметры
		super(factory, scope, rand); this.parameters = parameters;
    }
	@Override public KeyPair generate(String keyOID) throws IOException   
	{
        // получить фабрику кодирования
        aladdin.capi.KeyFactory keyFactory = factory().getKeyFactory(keyOID); 
        
		// определить параметры алгоритма
		BigInteger P = parameters.bdhP(); 
        BigInteger G = parameters.bdhG(); BigInteger X;

        // указать генератор случайных чисел
        try (Random random = new Random(rand())) 
        {
            // сгенерировать случайное число X
            do { X = new BigInteger(parameters.bdhR(), random); }

            // проверить выполнение требуемых условий
            while (X.signum() == 0 || X.compareTo(P) >= 0);
        }
		// возвести параметр G в степень x
		BigInteger Y = (new MontGroup(P)).power(G, X);

		// создать открытый ключ 
		IPublicKey publicKey = new BDHPublicKey(keyFactory, parameters, Y); 

		// создать открытый ключ и личный ключ 
        try (IPrivateKey privateKey = new BDHPrivateKey(
            factory(), scope(), keyOID, parameters, X))
        {
            // вернуть созданную пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
	}
}
