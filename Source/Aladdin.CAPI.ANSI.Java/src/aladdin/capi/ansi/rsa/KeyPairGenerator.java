package aladdin.capi.ansi.rsa;
import aladdin.capi.*; 
import java.math.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей RSA
///////////////////////////////////////////////////////////////////////////
public class KeyPairGenerator 
    extends aladdin.capi.software.KeyPairGenerator 
{
    // параметры генерации
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
        
		// используемые константы
		BigInteger E = parameters.getPublicExponent(); 
        
        // определить размер модуля в битах
        int bits = parameters.getModulusBits(); 
        
        // определить размер простых чисел в битах
        int lenP = bits / 2; int lenQ = bits - lenP;
        
    	// создать вспомогательные переменные
		BigInteger N; BigInteger P; BigInteger Q; 

        // указать генератор случайных чисел
        try (Random random = new Random(rand())) 
        {
            do {
                // сгенерировать первый и второй сомножители
                P = new BigInteger(lenP, 80, random);
                Q = new BigInteger(lenQ, 80, random);

                // вычислить модуль
                N = P.multiply(Q);
            }
            // проверить выполнение требуемых условий
            while (P.compareTo(Q) == 0 || N.bitLength() != bits);
        }
        // вычислить P-1 и Q-1
		BigInteger P1 = P.subtract(BigInteger.ONE); 
		BigInteger Q1 = Q.subtract(BigInteger.ONE);

		// вычислить секретную экспоненту
		BigInteger D = E.modInverse(P1.multiply(Q1)); 

		// создать открытый ключ 
		IPublicKey publicKey = new PublicKey(keyFactory, N, E); 
            
		// создать личный ключ 
		try (IPrivateKey privateKey = new PrivateKey(factory(), scope(), 
            keyOID, N, E, D, P, Q, D.mod(P1), D.mod(Q1), Q.modInverse(P)))
        {
            // вернуть созданную пару ключей
            return new KeyPair(publicKey, privateKey, null); 
        }
	}
}
