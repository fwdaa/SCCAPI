package aladdin.capi.keyx;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.capi.KeyPair;
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа ESDH на основе SSDH
///////////////////////////////////////////////////////////////////////////
public class ESDH extends RefObject implements ITransportAgreement
{
    // фабрика алгоритмов и алгоритм SSDH
    private final Factory factory; private final ITransportAgreement ssdh; 
    
    // конструктор
    public ESDH(Factory factory, ITransportAgreement ssdh)
    {
        // сохранить переданные параметры
        this.factory = RefObject.addRef(factory); this.ssdh = RefObject.addRef(ssdh); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(ssdh); RefObject.release(factory); super.onClose();
    } 
    // действия стороны-отправителя
    @Override public TransportAgreementData wrap(IPrivateKey senderPrivateKey, 
        IPublicKey senderPublicKey, IPublicKey[] recipientPublicKeys, IRand rand, ISecretKey key) 
        throws IOException, InvalidKeyException
    {
        // создать алгорим генерации ключей
        try (aladdin.capi.KeyPairGenerator generator = factory.createGenerator(
            null, rand, recipientPublicKeys[0].keyOID(), recipientPublicKeys[0].parameters())) 
        { 
            // сгенерировать эфемерную пару ключей
            try (KeyPair keyPair = generator.generate(null, recipientPublicKeys[0].keyOID(), 
                new KeyUsage(KeyUsage.KEY_AGREEMENT), KeyFlags.NONE))
            {
                // зашифровать ключ
                return ssdh.wrap(keyPair.privateKey, keyPair.publicKey, recipientPublicKeys, rand, key); 
            }
        }
    }
    // действия стороны-получателя
    @Override public ISecretKey unwrap(IPrivateKey recipientPrivateKey, 
        IPublicKey publicKey, byte[] random, 
        byte[] encryptedKey, SecretKeyFactory keyFactory) throws IOException
    {
        // расшифровать ключ
        return ssdh.unwrap(recipientPrivateKey, publicKey, random, encryptedKey, keyFactory); 
    }
}
