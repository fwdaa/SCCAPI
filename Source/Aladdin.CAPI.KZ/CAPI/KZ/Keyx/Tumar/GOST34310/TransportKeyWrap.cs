using System;

namespace Aladdin.CAPI.KZ.Keyx.Tumar.GOST34310
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм ассиметричного зашифрования ключа
    ///////////////////////////////////////////////////////////////////////
    public class TransportKeyWrap : CAPI.TransportKeyWrap
    {
	    // зашифровать ключ
	    public override TransportKeyData Wrap(
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, 
            IPublicKey publicKey, IRand rand, ISecretKey key)
        {
            // получить значение ключа
            byte[] data = key.Value; if (data == null) throw new InvalidKeyException(); 

            // проверить корректность данных
            if (data.Length != 32) throw new InvalidKeyException(); 

            // преобразовать тип параметров
            GOST.GOSTR3410.IECParameters ecParameters = 
                (GOST.GOSTR3410.IECParameters)publicKey.Parameters; 

            // преобразовать тип ключа
            GOST.GOSTR3410.IECPublicKey ecPublicKey = 
                (GOST.GOSTR3410.IECPublicKey)publicKey; 

	        // получить параметры алгоритма
	        EC.Point P = ecParameters.Generator; Math.BigInteger k = null; 

            // извлечь параметры алгоритма
            Math.BigInteger n = ecParameters.Order; int bitsN = n.BitLength;
            
            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            do { 
	            // сгенерировать случайное число
	            k = new Math.BigInteger(bitsN, random); 
            }
            // проверить выполнение требуемых условий
	        while (k.Signum == 0 || k.CompareTo(n) >= 0); 

            // вычислить кратную точку на эллиптической кривой
            EC.Point R = ecParameters.Curve.Multiply(P, k); 

            // вычислить кратную точку на эллиптической кривой
            EC.Point C = ecParameters.Curve.Multiply(ecPublicKey.Q, k); 

            // выбелить буферы требуемого размера
            byte[] rBlob = new byte[64]; byte[] sBlob = new byte[64]; 
    
            // закодировать большие числа
            Math.Convert.FromBigInteger(R.X, Math.Endian.LittleEndian, rBlob,  0, 32); 
            Math.Convert.FromBigInteger(R.Y, Math.Endian.LittleEndian, rBlob, 32, 32); 

            // закодировать большие числа
            Math.Convert.FromBigInteger(C.X, Math.Endian.BigEndian, sBlob,  0, 32); 
            Math.Convert.FromBigInteger(C.Y, Math.Endian.BigEndian, sBlob, 32, 32); 

            // выполнить поразрядное сложение
            for (int i = 0; i < data.Length; i++) sBlob[i] ^= data[i]; 

            // изменить порядок следования байт
            Arrays.Reverse(sBlob, 0, 32); Arrays.Reverse(sBlob, 32, 32);

            // объединить два представления
            byte[] encryptedKey = EncodeData(Arrays.Concat(rBlob, sBlob), rand);

            // вернуть описание зашифрованного ключа
            return new TransportKeyData(algorithmParameters, encryptedKey); 
        }
        // выполнить форматирование данных
        protected virtual byte[] EncodeData(byte[] rs, IRand rand)
        {
            // сгенерировать синхропосылку
            byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

            // указать заголовок данных
            byte[] blobHeader = new byte[] { 
                0x01, 0x02, 0x00, 0x00, // SIMPLEBLOB
                0x20, 0x66, 0x04, 0x00, // CALG_GOST-CFB
                0x20, 0xA0, 0x00, 0x00, // CALG_ELGAM
            }; 
            // извлечь значения R и S
            byte[] r = new byte[64]; Array.Copy(rs,  0, r, 0, 64);
            byte[] s = new byte[64]; Array.Copy(rs, 64, s, 0, 64);
            
            // закодировать зашифрованный ключ
            ASN1.IEncodable encryptedKey = new ASN1.KZ.EncryptedKey(
                new ASN1.Integer(4), new ASN1.OctetString(iv), 
                new ASN1.OctetString(r), new ASN1.OctetString(s), null
            ); 
            // объединить заголовок и зашифрованный ключ
            return Arrays.Concat(blobHeader, encryptedKey.Encoded); 
        }
    }
}
