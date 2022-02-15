using System;

namespace Aladdin.CAPI.KZ.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры ключа RSA
    ///////////////////////////////////////////////////////////////////////////
    public class KeyFactory : CAPI.ANSI.RSA.KeyFactory
    {
        // параметры ключа 
        private CAPI.ANSI.RSA.IParameters parameters; 

        // конструктор
        public KeyFactory(string keyOID) : base(keyOID) 
        {
            // в зависимости от идентификатора ключа
            if (keyOID == ASN1.KZ.OID.gamma_key_rsa_1024 || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1024_xch)
            {
                // указать параметры ключа
                parameters = new ANSI.RSA.Parameters(1024, null); 
            }
            // в зависимости от идентификатора ключа
            else if (keyOID == ASN1.KZ.OID.gamma_key_rsa_1536 || 
                     keyOID == ASN1.KZ.OID.gamma_key_rsa_1536_xch)
            {
                // вернуть параметры алгоритма
                parameters = new ANSI.RSA.Parameters(1536, null); 
            }
            // в зависимости от идентификатора ключа
            else if (keyOID == ASN1.KZ.OID.gamma_key_rsa_2048 || 
                     keyOID == ASN1.KZ.OID.gamma_key_rsa_2048_xch)
            {
                // вернуть параметры алгоритма
                parameters = new ANSI.RSA.Parameters(2048, null); 
            }
            // в зависимости от идентификатора ключа
            else if (keyOID == ASN1.KZ.OID.gamma_key_rsa_3072 || 
                     keyOID == ASN1.KZ.OID.gamma_key_rsa_3072_xch)
            {
                // вернуть параметры алгоритма
                parameters = new ANSI.RSA.Parameters(3072, null); 
            }
            // в зависимости от идентификатора ключа
            else if (keyOID == ASN1.KZ.OID.gamma_key_rsa_4096 || 
                     keyOID == ASN1.KZ.OID.gamma_key_rsa_4096_xch)
            {
                // вернуть параметры алгоритма
                parameters = new ANSI.RSA.Parameters(4096, null); 
            }
            // при ошибке выбросить исключение
            else throw new NotSupportedException(); 
        }
	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // для специальных ключей
            if (KeyOID == ASN1.KZ.OID.gamma_key_rsa_1024 || 
                KeyOID == ASN1.KZ.OID.gamma_key_rsa_1536 || 
                KeyOID == ASN1.KZ.OID.gamma_key_rsa_2048)
            {
            // указать способ использования ключа
            return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                   KeyUsage.CrlSignature     | KeyUsage.NonRepudiation;       
            }
            // вызвать базовую функцию
            return base.GetKeyUsage(); 
        }
        // закодировать параметры
        public override ASN1.IEncodable EncodeParameters(
            CAPI.IParameters parameters) { return ASN1.Null.Instance; }

        // раскодировать параметры
        public override CAPI.IParameters 
            DecodeParameters(ASN1.IEncodable encoded) { return parameters; }
    }
}
