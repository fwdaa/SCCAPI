package aladdin.capi.kz.keyx.tumar.gost34310;
import aladdin.math.*; 
import aladdin.asn1.*; 
import aladdin.asn1.kz.*; 
import aladdin.capi.*; 
import aladdin.capi.gost.gostr3410.*; 
import aladdin.util.*; 
import java.security.spec.*; 
import java.math.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////
// Алгоритм ассиметричного расшифрования ключа
///////////////////////////////////////////////////////////////////////
public class TransportKeyUnwrap extends aladdin.capi.TransportKeyUnwrap
{
    // расшифровать данные
    @Override public ISecretKey unwrap(IPrivateKey privateKey, 
        TransportKeyData transportData, SecretKeyFactory keyFactory) throws IOException
    {
        // удалить форматирование данных
        byte[] data = decodeData(transportData.encryptedKey); 

        // проверить корректность данных
        if (data.length != 128) throw new IOException(); 

        // преобразовать тип параметров
        IECParameters ecParameters = (IECParameters)privateKey.parameters(); 

        // преобразовать тип ключа
        IECPrivateKey ecPrivateKey = (IECPrivateKey)privateKey; 

        // извлечь первую часть
        byte[] rBlob = new byte[64]; System.arraycopy(data,  0, rBlob, 0, 64); 
        byte[] sBlob = new byte[64]; System.arraycopy(data, 64, sBlob, 0, 64); 
        byte[] cBlob = new byte[64]; 

        // изменить порядок следования байт
        Array.reverse(sBlob, 0, 32); Array.reverse(sBlob, 32, 32);

        // раскодировать большие числа
        BigInteger RX = Convert.toBigInteger(rBlob,  0, 32, Endian.LITTLE_ENDIAN); 
        BigInteger RY = Convert.toBigInteger(rBlob, 32, 32, Endian.LITTLE_ENDIAN); 

        // создать точку на эллиптической кривой
        ECPoint R = new ECPoint(RX, RY); 

        // вычислить кратную точку на эллиптической кривой
        ECPoint C = ecParameters.getCurve().multiply(R, ecPrivateKey.getS()); 

        // закодировать большие числа
        Convert.fromBigInteger(C.getAffineX(), Endian.BIG_ENDIAN, cBlob,  0, 32); 
        Convert.fromBigInteger(C.getAffineY(), Endian.BIG_ENDIAN, cBlob, 32, 32); 

        // выполнить поразрядное сложение
        for (int i = 0; i < sBlob.length; i++) sBlob[i] ^= cBlob[i]; 
                
        // выполнить сжатие данных
        return keyFactory.create(Arrays.copyOf(sBlob, 32)); 
    }
    // удалить форматирование данных
    protected byte[] decodeData(byte[] data) throws IOException
    {
        // проверить размер данных
        if (data.length < 12) throw new IOException(); 

        // проверить корректность заголовка
        if (data[0] != 1 || data[1] != 2) throw new IOException();

        // раскодировать зашифрованный ключ
        EncryptedKey encryptedKey = new EncryptedKey(
            Encodable.decode(data, 12, data.length - 12)
        ); 
        // проверить корректность данных
        if (encryptedKey.ukm() != null) throw new IOException(); 
            
        // сформировать данные
        return Array.concat(encryptedKey.spc().value(), encryptedKey.encrypted().value()); 
    }
}

