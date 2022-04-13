using System; 

namespace Aladdin.CAPI.ANSI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Преобразования имен ключей и алгоритмов
    ///////////////////////////////////////////////////////////////////////////////
    public static class Aliases
    {
        ///////////////////////////////////////////////////////////////////////////
        // Получить идентификатор ключа
        ///////////////////////////////////////////////////////////////////////////
        public static string ConvertKeyName(string name)
        {
            // проверить наличие идентификатора
            if (name.Contains(".")) return name; 

            // указать идентификатор алгоритма
            if (String.Compare(name, "RSA", true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa;      
            if (String.Compare(name, "DH" , true) == 0) return ASN1.ANSI.OID.x942_dh_public_key; 
            if (String.Compare(name, "DSA", true) == 0) return ASN1.ANSI.OID.x957_dsa;           
            if (String.Compare(name, "EC" , true) == 0) return ASN1.ANSI.OID.x962_ec_public_key; 

            return name; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Получить идентификатор алгоритма
        ///////////////////////////////////////////////////////////////////////////
        public static string ConvertAlgorithmName(string name)
        {
            // проверить наличие идентификатора
            if (name.Contains(".")) return name; 

            // стандартные алгоритмы хэширования 
            if (String.Compare(name, "MD2"                     , true) == 0) return ASN1.ANSI.OID.rsa_md2; 
            if (String.Compare(name, "MD5"                     , true) == 0) return ASN1.ANSI.OID.rsa_md5; 
            if (String.Compare(name, "SHA-1"                   , true) == 0) return ASN1.ANSI.OID.ssig_sha1; 
            if (String.Compare(name, "SHA-256"                 , true) == 0) return ASN1.ANSI.OID.nist_sha2_256; 
            if (String.Compare(name, "SHA-384"                 , true) == 0) return ASN1.ANSI.OID.nist_sha2_384; 
            if (String.Compare(name, "SHA-512"                 , true) == 0) return ASN1.ANSI.OID.nist_sha2_512; 

            // стандартные алгоритмы вычисления имитовставки
            if (String.Compare(name, "HmacMD5"                 , true) == 0) return ASN1.ANSI.OID.ipsec_hmac_md5; 
            if (String.Compare(name, "HmacSHA1"                , true) == 0) return ASN1.ANSI.OID.rsa_hmac_sha1; 
            if (String.Compare(name, "HmacSHA256"              , true) == 0) return ASN1.ANSI.OID.rsa_hmac_sha2_256; 
            if (String.Compare(name, "HmacSHA384"              , true) == 0) return ASN1.ANSI.OID.rsa_hmac_sha2_384; 
            if (String.Compare(name, "HmacSHA512"              , true) == 0) return ASN1.ANSI.OID.rsa_hmac_sha2_512; 

            // стандартные алгоритмы шифрования данных
            if (String.Compare(name, "RC4"                     , true) == 0) return ASN1.ANSI.OID.rsa_rc4; 
            if (String.Compare(name, "PBEWithMD2AndDES"        , true) == 0) return ASN1.ISO.PKCS.PKCS5.OID.pbe_md2_des_cbc;
            if (String.Compare(name, "PBEWithMD5AndDES"        , true) == 0) return ASN1.ISO.PKCS.PKCS5.OID.pbe_md5_des_cbc; 
            if (String.Compare(name, "PBEWithMD2AndRC2_64"     , true) == 0) return ASN1.ISO.PKCS.PKCS5.OID.pbe_md2_rc2_64_cbc;
            if (String.Compare(name, "PBEWithMD5AndRC2_64"     , true) == 0) return ASN1.ISO.PKCS.PKCS5.OID.pbe_md5_rc2_64_cbc;
            if (String.Compare(name, "PBEWithSHA1AndDES"       , true) == 0) return ASN1.ISO.PKCS.PKCS5.OID.pbe_sha1_des_cbc;
            if (String.Compare(name, "PBEWithSHA1AndRC2_64"    , true) == 0) return ASN1.ISO.PKCS.PKCS5.OID.pbe_sha1_rc2_64_cbc;
            if (String.Compare(name, "PBEWithSHA1AndRC4_128"   , true) == 0) return ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc4_128;
            if (String.Compare(name, "PBEWithSHA1AndRC4_40"    , true) == 0) return ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc4_40;
            if (String.Compare(name, "PBEWithSHA1AndRC2_128"   , true) == 0) return ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc2_128_cbc;
            if (String.Compare(name, "PBEWithSHA1AndRC2_40"    , true) == 0) return ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc2_40_cbc; 
            if (String.Compare(name, "PBEWithSHA1AndDESede_192", true) == 0) return ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_192_cbc;
            if (String.Compare(name, "PBEWithSHA1AndDESede_128", true) == 0) return ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_128_cbc;
            if (String.Compare(name, "PBEWithSHA1AndAES_128"   , true) == 0) return ASN1.ANSI.OID.bc_pbe_sha1_pkcs12_aes128_cbc;
            if (String.Compare(name, "PBEWithSHA1AndAES_192"   , true) == 0) return ASN1.ANSI.OID.bc_pbe_sha1_pkcs12_aes192_cbc;
            if (String.Compare(name, "PBEWithSHA1AndAES_256"   , true) == 0) return ASN1.ANSI.OID.bc_pbe_sha1_pkcs12_aes256_cbc;
            if (String.Compare(name, "PBEWithSHA256AndAES_128" , true) == 0) return ASN1.ANSI.OID.bc_pbe_sha2_256_pkcs12_aes128_cbc;
            if (String.Compare(name, "PBEWithSHA256AndAES_192" , true) == 0) return ASN1.ANSI.OID.bc_pbe_sha2_256_pkcs12_aes192_cbc;
            if (String.Compare(name, "PBEWithSHA256AndAES_256" , true) == 0) return ASN1.ANSI.OID.bc_pbe_sha2_256_pkcs12_aes256_cbc;

            // стандартные алгоритмы шифрования ключа
            if (String.Compare(name, "DESedeWrap"              , true) == 0) return ASN1.ISO.PKCS.PKCS9.OID.smime_tdes192_wrap;
            if (String.Compare(name, "AESWrap_128"             , true) == 0) return ASN1.ANSI.OID.nist_aes128_wrap;
            if (String.Compare(name, "AESWrap_192"             , true) == 0) return ASN1.ANSI.OID.nist_aes192_wrap;
            if (String.Compare(name, "AESWrap_256"             , true) == 0) return ASN1.ANSI.OID.nist_aes256_wrap;

            // стандартные алгоритмы асимметричного шифрования
            if (String.Compare(name, "RSA"                     , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa;  
            if (String.Compare(name, "RSA/PKCS1Padding"        , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa;  
            if (String.Compare(name, "RSA/OAEPPadding"         , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep;

            // стандартные алгоритмы подписи данных
            if (String.Compare(name, "MD2withRSA"              , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa_md2;
            if (String.Compare(name, "MD5withRSA"              , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa_md5;
            if (String.Compare(name, "SHA1withRSA"             , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1;
            if (String.Compare(name, "SHA256withRSA"           , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_256;
            if (String.Compare(name, "SHA384withRSA"           , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_384;
            if (String.Compare(name, "SHA512withRSA"           , true) == 0) return ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512;
            if (String.Compare(name, "SHA1withDSA"             , true) == 0) return ASN1.ANSI.OID.x957_dsa_sha1;
            if (String.Compare(name, "SHA1withECDSA"           , true) == 0) return ASN1.ANSI.OID.x962_ecdsa_sha1;
            if (String.Compare(name, "SHA256withECDSA"         , true) == 0) return ASN1.ANSI.OID.x962_ecdsa_sha2_256;
            if (String.Compare(name, "SHA384withECDSA"         , true) == 0) return ASN1.ANSI.OID.x962_ecdsa_sha2_384;
            if (String.Compare(name, "SHA512withECDSA"         , true) == 0) return ASN1.ANSI.OID.x962_ecdsa_sha2_512; 

            // стандартные алгоритмы согласования общего ключа
            if (String.Compare(name, "DiffieHellman"           , true) == 0) return ASN1.ANSI.OID.x942_dh_public_key;
            if (String.Compare(name, "ECDH"                    , true) == 0) return ASN1.ANSI.OID.x962_ec_public_key; 

            return name; 
        }
    }
}
