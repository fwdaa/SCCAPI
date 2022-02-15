using System;
using System.IO;

namespace Aladdin.CAPI.KZ.Keyx.Tumar.GOST34310
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм ассиметричного расшифрования ключа
    ///////////////////////////////////////////////////////////////////////
    public class TransportKeyUnwrap : CAPI.TransportKeyUnwrap
    {
	    // расшифровать данные
	    public override ISecretKey Unwrap(IPrivateKey privateKey, 
            TransportKeyData transportData, SecretKeyFactory keyFactory)
        {
            // удалить форматирование данных
            byte[] data = DecodeData(transportData.EncryptedKey); 

            // проверить корректность данных
            if (data.Length != 128) throw new InvalidDataException(); 

            // преобразовать тип параметров
            GOST.GOSTR3410.IECParameters ecParameters = 
                (GOST.GOSTR3410.IECParameters)privateKey.Parameters; 

            // преобразовать тип ключа
            GOST.GOSTR3410.IECPrivateKey ecPrivateKey = 
                (GOST.GOSTR3410.IECPrivateKey)privateKey; 

            // извлечь первую часть
            byte[] rBlob = new byte[64]; Array.Copy(data,  0, rBlob, 0, 64); 
            byte[] sBlob = new byte[64]; Array.Copy(data, 64, sBlob, 0, 64); 
            byte[] cBlob = new byte[64]; 

            // изменить порядок следования байт
            Arrays.Reverse(sBlob, 0, 32); Arrays.Reverse(sBlob, 32, 32);

            // раскодировать большие числа
            Math.BigInteger RX = Math.Convert.ToBigInteger(rBlob,  0, 32, Math.Endian.LittleEndian); 
            Math.BigInteger RY = Math.Convert.ToBigInteger(rBlob, 32, 32, Math.Endian.LittleEndian); 

            // создать точку на эллиптической кривой
            EC.Point R = new EC.Point(RX, RY); 

            // вычислить кратную точку на эллиптической кривой
            EC.Point C = ecParameters.Curve.Multiply(R, ecPrivateKey.D); 

            // закодировать большие числа
            Math.Convert.FromBigInteger(C.X, Math.Endian.BigEndian, cBlob,  0, 32); 
            Math.Convert.FromBigInteger(C.Y, Math.Endian.BigEndian, cBlob, 32, 32); 

            // выполнить поразрядное сложение
            for (int i = 0; i < sBlob.Length; i++) sBlob[i] ^= cBlob[i]; 
            
            // выполнить сжатие данных
            return keyFactory.Create(Arrays.CopyOf(sBlob, 0, 32)); 
        }
        // удалить форматирование данных
        protected virtual byte[] DecodeData(byte[] data)
        {
            // проверить размер данных
            if (data.Length < 12) throw new InvalidDataException(); 

            // проверить корректность заголовка
            if (data[0] != 1 || data[1] != 2) throw new InvalidDataException();

            // раскодировать зашифрованный ключ
            ASN1.KZ.EncryptedKey encryptedKey = new ASN1.KZ.EncryptedKey(
                ASN1.Encodable.Decode(data, 12, data.Length - 12)
            ); 
            // проверить корректность данных
            if (encryptedKey.UKM != null) throw new InvalidDataException(); 

            // сформировать данные
            return Arrays.Concat(encryptedKey.Spc.Value, encryptedKey.Encrypted.Value); 
        }
    }
}
