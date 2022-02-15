package aladdin.capi.stb.stb11762;
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации двойных ключей СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public class BDSBDHKeyPairGenerator extends aladdin.capi.software.KeyPairGenerator
{
    // параметры ключей
	private final IBDSBDHParameters parameters;

	// конструктор
	public BDSBDHKeyPairGenerator(Factory factory, 
        SecurityObject scope, IRand rand, IBDSBDHParameters parameters)
    { 
        // сохранить переданные параметры
		super(factory, scope, rand); this.parameters = parameters;
    }
	@Override public KeyPair generate(String keyOID) throws IOException  
	{
        // получить фабрику кодирования
        aladdin.capi.KeyFactory keyFactory = factory().getKeyFactory(keyOID); 
        
		// создать алгоритм генерации ключей
		try (BDSKeyPairGenerator bdsGenerator = new BDSKeyPairGenerator(
            factory(), scope(), rand(), parameters))
		{
			// сгенерировать пару ключей
			try (KeyPair bdsKeyPair = bdsGenerator.generate(keyOID)) 
			{
				// создать алгоритм генерации ключей
				try (BDHKeyPairGenerator bdhGenerator = new BDHKeyPairGenerator(
                    factory(), scope(), rand(), parameters))
				{
					// сгенерировать пару ключей
					try (KeyPair bdhKeyPair = bdhGenerator.generate(keyOID))
					{
						// создать открытый ключ подписи/обмена
						IBDSBDHPublicKey publicKey = new BDSBDHPublicKey(
            				keyFactory, parameters,
							((IBDSPublicKey)bdsKeyPair.publicKey).bdsY(), 
							((IBDHPublicKey)bdhKeyPair.publicKey).bdhY() 
						);
						// создать личный ключ подписи/обмена
						try (IBDSBDHPrivateKey privateKey = new BDSBDHPrivateKey(
            				factory(), scope(), keyOID, parameters,
							((IBDSPrivateKey)bdsKeyPair.privateKey).bdsX(), 
							((IBDHPrivateKey)bdhKeyPair.privateKey).bdhX()))
        				{
            				// вернуть созданную пару ключей
            				return new KeyPair(publicKey, privateKey, null); 
        				}
					}
				} 
			}
		}
	}
}
