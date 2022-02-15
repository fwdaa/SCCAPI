using System;

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3410
{
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритм согласования ключа ГОСТ Р 34.10
    ////////////////////////////////////////////////////////////////////////////
    public class TransportAgreement : CAPI.TransportAgreement
    {
        // конструктор
        public static new TransportAgreement CreateSSDH(
            CAPI.Factory factory, SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters)
        {
            // раскодировать параметры
            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

            // извлечь идентификатор алгоритма шифрования ключа
            string wrapOID = wrapParameters.Algorithm.Value;

            // раскодировать параметры
            ASN1.GOST.KeyWrapParameters keyWrapParameters = 
                new ASN1.GOST.KeyWrapParameters(wrapParameters.Parameters); 

            // извлечь идентификатор таблицы подстановок
            string sboxOID = keyWrapParameters.ParamSet.Value;

            // указать параметры алгоритма
            keyWrapParameters = new ASN1.GOST.KeyWrapParameters(
                new ASN1.ObjectIdentifier(sboxOID), new ASN1.OctetString(new byte[8])
            ); 
            // указать идентификатор алгоритма
            wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(wrapOID), keyWrapParameters
            );
            // создать алгоритм шифрования ключа
            using (IAlgorithm keyWrap = 
                factory.CreateAlgorithm<KeyWrap>(scope, wrapParameters))
            {
                // проверить поддержку алгоритма
                if (keyWrap == null) return null;  
            }
            // создать алгоритм согласования ключа
            using (IAlgorithm keyAgreement = 
                factory.CreateAlgorithm<IKeyAgreement>(scope, parameters))
            {
                // проверить поддержку алгоритма
                if (keyAgreement == null) return null;  
            }
            // создать алгоритм шифрования ключа
            return new TransportAgreement(parameters); 
        }
        // конструктор
        public TransportAgreement(ASN1.ISO.AlgorithmIdentifier parameters) : base(parameters) {} 

        // закодировать зашифрованный ключ
        protected override byte[] EncodeEncryptedKey(byte[] encryptedKey) 
        { 
            // выделить память для зашифрованного ключа и имитовставки
            byte[] encryptedCEK = new byte[encryptedKey.Length - 4]; byte[] macCEK = new byte[4]; 

            // извлечь зашифрованный ключ
            Array.Copy(encryptedKey, 0, encryptedCEK, 0, encryptedCEK.Length);  

            // извлечь имитовставку
            Array.Copy(encryptedKey, encryptedCEK.Length, macCEK, 0, macCEK.Length);  

            // закодировать зашифрованный ключ
            ASN1.GOST.EncryptedKey encoded = new ASN1.GOST.EncryptedKey(
                new ASN1.OctetString(encryptedCEK), null, new ASN1.OctetString(macCEK)
            );
            // сохранить зашифрованный ключ
            return encoded.Encoded;         
        }    
        // раскодировать зашифрованный ключ
        protected override byte[] DecodeEncryptedKey(byte[] encryptedKey) 
        { 
            // извлечь зашифрованный ключ и имитовставку
            ASN1.GOST.EncryptedKey encoded = new ASN1.GOST.EncryptedKey(
                ASN1.Encodable.Decode(encryptedKey)
            ); 
            // извлечь зашифрованный ключ и имитовставку
            byte[] encryptedCEK = encoded.Encrypted.Value; 
            byte[] macCEK       = encoded.MacKey   .Value;

            // создать структуру зашифрованного ключа
            return Arrays.Concat(encryptedCEK, macCEK); 
        }    
        // получить алгоритм шифрования ключа
        protected override KeyWrap CreateKeyWrapAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, byte[] ukm)
        {
            // раскодировать параметры
            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

            // извлечь идентификатор алгоритма шифрования ключа
            string wrapOID = wrapParameters.Algorithm.Value;

            // раскодировать параметры
            ASN1.GOST.KeyWrapParameters keyWrapParameters = 
                new ASN1.GOST.KeyWrapParameters(wrapParameters.Parameters); 

            // извлечь идентификатор таблицы подстановок
            string sboxOID = keyWrapParameters.ParamSet.Value;

            // указать параметры алгоритма
            keyWrapParameters = new ASN1.GOST.KeyWrapParameters(
                new ASN1.ObjectIdentifier(sboxOID), new ASN1.OctetString(ukm)
            ); 
            // указать идентификатор алгоритма
            wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(wrapOID), keyWrapParameters
            );
            // получить алгоритм шифрования ключа
            KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, wrapParameters); 

            // проверить наличие алгоритма
            if (algorithm == null) throw new NotSupportedException(); return algorithm; 
        }
    }
}
