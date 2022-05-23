package aladdin.capi.pkcs11.athena.x962;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей EC/ECDSA
///////////////////////////////////////////////////////////////////////////
public class KeyPairGenerator extends aladdin.capi.ansi.pkcs11.x962.KeyPairGenerator
{
    // конструктор
    public KeyPairGenerator(Applet applet, SecurityObject scope, 

        // сохранить переданные параметры
        IRand rand, aladdin.capi.ansi.x962.Parameters parameters) throws IOException
    {
        // сохранить переданные параметры
        super(applet, scope, rand, parameters); 
    }
	// сгенерировать пару ключей
	@Override public KeyPair generate(byte[] keyID, 
        String keyOID, KeyUsage keyUsage, KeyFlags keyFlags) throws IOException
    {
        // сгенерировать пару ключей
        try (KeyPair keyPair = generate(keyOID, keyUsage))
        {
            // проверить необходимость записи
            if (!(scope() instanceof aladdin.capi.Container)) return RefObject.addRef(keyPair); 

            // записать пару ключей на смарт-карту
            return ((aladdin.capi.Container)scope()).importKeyPair(
                rand(), keyPair.publicKey, keyPair.privateKey, keyUsage, keyFlags
            ); 
        }
    }
}
