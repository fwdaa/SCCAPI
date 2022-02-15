package aladdin.capi.software;
import aladdin.capi.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации программных ключей
///////////////////////////////////////////////////////////////////////////
public abstract class KeyPairGenerator extends aladdin.capi.KeyPairGenerator
{
    // конструктор
    public KeyPairGenerator(Factory factory, SecurityObject scope, IRand rand) 
    { 
        // сохранить генератор случайных данных
        super(factory, scope, rand); 
    } 
	// сгенерировать ключи
    @Override 
    public KeyPair generate(byte[] keyID, String keyOID, 
        KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
	{
		// сгенерировать ключи
		try (KeyPair keyPair = generate(keyOID)) 
        {
            // записать ключи в контейнер
            return keyPair.copyTo(rand(), scope(), keyUsage, keyFlags); 
        }
	}
	// сгенерировать ключи
	public abstract KeyPair generate(String keyOID) throws IOException;
}
