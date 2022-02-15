package aladdin.capi.gost.keyx.gostr3412;
import aladdin.capi.gost.keyx.gostr3410.*;
import aladdin.*;
import aladdin.capi.*;
import aladdin.capi.derive.*;
import aladdin.capi.gost.gostr3410.*; 
import aladdin.util.*;
import java.io.*;
import java.security.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа KEG (личный ключ 32 байта)
///////////////////////////////////////////////////////////////////////////
public class KEG2012_256 extends ECKeyAgreement2012 
{
    // алгоритм HMAC и синхропосылка
    private final Mac hmac_gostr3411_2012_256; 
    
    // конструктор
    public KEG2012_256(Mac hmac_gostr3411_2012_256) 
    {
        // сохранить переданные параметры
        this.hmac_gostr3411_2012_256 = RefObject.addRef(hmac_gostr3411_2012_256); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    { 
        // освободить выделенные ресурсы
        RefObject.release(hmac_gostr3411_2012_256); super.onClose();         
    } 
    // размер случайных данных
    @Override protected int randomSize() { return 32; }
    
    // сгенерировать случайные данные
    @Override public byte[] generate(IParameters parameters, IRand rand) throws IOException
    {
        // выделить память для случайных данных
        byte[] random = new byte[randomSize()]; 
        
        // сгенерировать случайные данные
        rand.generate(random, 0, random.length); return random; 
    }
 	// согласовать общий ключ на стороне получателя
	@Override public ISecretKey deriveKey(IPrivateKey privateKey, 
        IPublicKey publicKey, byte[] random, 
        SecretKeyFactory keyFactory, int keySize) throws IOException
    {
        // проверить указание размера
        if (keySize < 0) keySize = 64; if (keySize != 64) throw new IOException();
        
        // скопировать часть случайных данных
        byte[] r = new byte[16]; System.arraycopy(random, 0, r, 0, r.length);
        
        // для случайных данных
        boolean zero = true; for (int i = 0; i < r.length; i++)
        {
            // проверить отсутствие нулевых данных
            if (random[i] != 0) { zero = false; break; }
        }
        // скорректировать нулевые данные
        Array.reverse(r); if (zero) r[0] = 0x1; 
        
        // преобразовать тип параметров
        IECParameters parameters = (IECParameters) privateKey.parameters(); 
        
        // определить размер личного ключа
        int privateKeyLength = (parameters.getOrder().bitLength() + 7) / 8; 

        // проверить корректность размера
        if (privateKeyLength != keySize / 2) throw new IOException(); 
            
        // указать фабрику создания ключа
        SecretKeyFactory genericKeyFactory = SecretKeyFactory.GENERIC; 
            
        // согласовать общий ключ
        try (ISecretKey key = super.deriveKey(privateKey, publicKey, r, genericKeyFactory, keySize / 2))
        {
            // создать алгоритм наследования ключа
            try (KeyDerive keyDerive = createKDF_TREE("kdf tree".getBytes("ASCII"), 1))
            {
                // извлечь значение синхропосылки 
                byte[] seed = new byte[8]; System.arraycopy(random, 16, seed, 0, seed.length);
        
                // увеличить размер ключа
                return keyDerive.deriveKey(key, seed, keyFactory, keySize); 
            }
            // обработать возможную ошибку
            catch (InvalidKeyException e) { throw new IOException(e); }
        }
    }
    // создать алгоритм наследования
    protected KeyDerive createKDF_TREE(byte[] label, int R) throws IOException  
    { 
        // создать алгоритм наследования
        if (hmac_gostr3411_2012_256 != null) return new TREEKDF(hmac_gostr3411_2012_256, label, R); 
        
        // создать алгоритм хэширования
        try (Hash hashAlgorithm = new aladdin.capi.gost.hash.GOSTR3411_2012(256))
        {
            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = new aladdin.capi.mac.HMAC(hashAlgorithm))
            {
                // создать алгоритм наследования
                return new TREEKDF(macAlgorithm, label, R); 
            }
        }
    }
}
