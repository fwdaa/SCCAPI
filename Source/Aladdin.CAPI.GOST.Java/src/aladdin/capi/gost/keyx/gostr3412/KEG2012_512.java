package aladdin.capi.gost.keyx.gostr3412;
import aladdin.capi.gost.keyx.gostr3410.*;
import aladdin.capi.*;
import aladdin.capi.gost.gostr3410.*; 
import aladdin.util.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа KEG (личный ключ 64 байта)
///////////////////////////////////////////////////////////////////////////
public class KEG2012_512 extends ECKeyAgreement2012 
{
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
        if (keySize != privateKeyLength) throw new IOException();
        
        // согласовать общий ключ
        return super.deriveKey(privateKey, publicKey, r, keyFactory, keySize); 
    }
}
