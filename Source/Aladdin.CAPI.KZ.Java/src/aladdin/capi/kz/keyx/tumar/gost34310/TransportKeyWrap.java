package aladdin.capi.kz.keyx.tumar.gost34310;
import aladdin.math.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.kz.*; 
import aladdin.capi.*; 
import aladdin.capi.ec.*; 
import aladdin.capi.gost.gostr3410.*; 
import aladdin.util.*; 
import java.security.*; 
import java.security.spec.*; 
import java.math.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Алгоритм ассиметричного зашифрования ключа
///////////////////////////////////////////////////////////////////////
public class TransportKeyWrap extends aladdin.capi.TransportKeyWrap
{
    // зашифровать ключ 
    @Override public TransportKeyData wrap(AlgorithmIdentifier algorithmParameters, 
        IPublicKey publicKey, IRand rand, ISecretKey key) throws IOException, InvalidKeyException
    {
        // получить значение ключа
        byte[] data = key.value(); if (data == null) throw new InvalidKeyException(); 

        // проверить корректность данных
        if (data.length != 32) throw new InvalidKeyException(); 

        // преобразовать тип параметров
        IECParameters ecParameters = (IECParameters)publicKey.parameters(); 

        // преобразовать тип ключа
        IECPublicKey ecPublicKey = (IECPublicKey)publicKey; 

        // получить параметры алгоритма
		Curve ec = ecParameters.getCurve(); 

        // извлечь параметры алгоритма
        BigInteger n = ecParameters.getOrder(); BigInteger k = BigInteger.ZERO; 

        // указать генератор случайных чисел
        try (Random random = new Random(rand)) 
        {
            // проверить выполнение требуемых условий
            for (int bitsN = n.bitLength(); k.signum() == 0 || k.compareTo(n) >= 0; )
            {
                // сгенерировать случайное число
                k = new BigInteger(bitsN, random); 
            }
        }
        // вычислить кратную точку на эллиптической кривой
        ECPoint R = ec.multiply(ecParameters.getGenerator(), k); 

        // вычислить кратную точку на эллиптической кривой
        ECPoint C = ec.multiply(ecPublicKey.getW(), k); 

        // выбелить буферы требуемого размера
        byte[] rBlob = new byte[64]; byte[] sBlob = new byte[64]; 
        
        // закодировать большие числа
        Convert.fromBigInteger(R.getAffineX(), Endian.LITTLE_ENDIAN, rBlob,  0, 32); 
        Convert.fromBigInteger(R.getAffineY(), Endian.LITTLE_ENDIAN, rBlob, 32, 32); 

        // закодировать большие числа
        Convert.fromBigInteger(C.getAffineX(), Endian.BIG_ENDIAN, sBlob,  0, 32); 
        Convert.fromBigInteger(C.getAffineY(), Endian.BIG_ENDIAN, sBlob, 32, 32); 

        // выполнить поразрядное сложение
        for (int i = 0; i < data.length; i++) sBlob[i] ^= data[i]; 

        // изменить порядок следования байт
        Array.reverse(sBlob, 0, 32); Array.reverse(sBlob, 32, 32);

        // объединить два представления
        byte[] encryptedKey = encodeData(Array.concat(rBlob, sBlob), rand);

        // вернуть описание зашифрованного ключа
        return new TransportKeyData(algorithmParameters, encryptedKey); 
    }
    // выполнить форматирование данных
    protected byte[] encodeData(byte[] rs, IRand rand) throws IOException
    {
        // сгенерировать случайные данные
        byte[] ukm = new byte[8]; rand.generate(ukm, 0, ukm.length); 

        // указать заголовок данных
        byte[] blobHeader = new byte[] { 
            (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00, // SIMPLEBLOB
            (byte)0x20, (byte)0x66, (byte)0x04, (byte)0x00, // CALG_GOST-CFB
            (byte)0x20, (byte)0xA0, (byte)0x00, (byte)0x00, // CALG_ELGAM
        }; 
        // извлечь значения R и S
        byte[] r = new byte[64]; System.arraycopy(rs,  0, r, 0, 64);
        byte[] s = new byte[64]; System.arraycopy(rs, 64, s, 0, 64);
            
        // закодировать зашифрованный ключ
        IEncodable encryptedKey = new EncryptedKey(
            new Integer(4), new OctetString(ukm), 
            new OctetString(r), new OctetString(s), null
        ); 
        // объединить заголовок и зашифрованный ключ
        return Array.concat(blobHeader, encryptedKey.encoded()); 
    }
}
