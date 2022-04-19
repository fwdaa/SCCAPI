package aladdin.capi.ansi;

///////////////////////////////////////////////////////////////////////////////
// Преобразования имен ключей и алгоритмов
///////////////////////////////////////////////////////////////////////////////
public class Aliases 
{
    ///////////////////////////////////////////////////////////////////////////
    // Получить идентификатор ключа
    ///////////////////////////////////////////////////////////////////////////
    public static String convertKeyName(String name)
    {
        // проверить наличие идентификатора
        if (name.contains(".")) return name; 
        
        // указать идентификатор ключа
        if (name.equalsIgnoreCase("RSA")) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA;      
        if (name.equalsIgnoreCase("DH" )) return aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY; 
        if (name.equalsIgnoreCase("DSA")) return aladdin.asn1.ansi.OID.X957_DSA;           
        if (name.equalsIgnoreCase("EC" )) return aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY; 
        
        return name; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Получить идентификатор алгоритма
    ///////////////////////////////////////////////////////////////////////////
    public static String convertAlgorithmName(String name)
    {
        // проверить наличие идентификатора
        if (name.contains(".")) return name; 
        
        // стандартные алгоритмы хэширования 
        if (name.equalsIgnoreCase("MD2"                     )) return aladdin.asn1.ansi.OID.RSA_MD2; 
        if (name.equalsIgnoreCase("MD5"                     )) return aladdin.asn1.ansi.OID.RSA_MD5; 
        if (name.equalsIgnoreCase("SHA-1"                   )) return aladdin.asn1.ansi.OID.SSIG_SHA1; 
        if (name.equalsIgnoreCase("SHA-256"                 )) return aladdin.asn1.ansi.OID.NIST_SHA2_256; 
        if (name.equalsIgnoreCase("SHA-384"                 )) return aladdin.asn1.ansi.OID.NIST_SHA2_384; 
        if (name.equalsIgnoreCase("SHA-512"                 )) return aladdin.asn1.ansi.OID.NIST_SHA2_512; 
        
        // стандартные алгоритмы вычисления имитовставки
        if (name.equalsIgnoreCase("HmacMD5"                 )) return aladdin.asn1.ansi.OID.IPSEC_HMAC_MD5; 
        if (name.equalsIgnoreCase("HmacSHA1"                )) return aladdin.asn1.ansi.OID.RSA_HMAC_SHA1; 
        if (name.equalsIgnoreCase("HmacSHA256"              )) return aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_256; 
        if (name.equalsIgnoreCase("HmacSHA384"              )) return aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_384; 
        if (name.equalsIgnoreCase("HmacSHA512"              )) return aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512; 
        
        // стандартные алгоритмы шифрования данных
        if (name.equalsIgnoreCase("RC4"                     )) return aladdin.asn1.ansi.OID.RSA_RC4; 
        if (name.equalsIgnoreCase("PBEWithMD2AndDES"        )) return aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD2_DES_CBC; 
        if (name.equalsIgnoreCase("PBEWithMD5AndDES"        )) return aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD5_DES_CBC;
        if (name.equalsIgnoreCase("PBEWithMD2AndRC2_64"     )) return aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD2_RC2_64_CBC;
        if (name.equalsIgnoreCase("PBEWithMD5AndRC2_64"     )) return aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD5_RC2_64_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndDES"       )) return aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_SHA1_DES_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndRC2_64"    )) return aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_SHA1_RC2_64_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndRC4_128"   )) return aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC4_128;
        if (name.equalsIgnoreCase("PBEWithSHA1AndRC4_40"    )) return aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC4_40;
        if (name.equalsIgnoreCase("PBEWithSHA1AndRC2_128"   )) return aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC2_128_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndRC2_40"    )) return aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC2_40_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndDESede_192")) return aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_TDES_192_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndDESede_128")) return aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_TDES_128_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndAES_128"   )) return aladdin.asn1.ansi.OID.BC_PBE_SHA1_PKCS12_AES128_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndAES_192"   )) return aladdin.asn1.ansi.OID.BC_PBE_SHA1_PKCS12_AES192_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA1AndAES_256"   )) return aladdin.asn1.ansi.OID.BC_PBE_SHA1_PKCS12_AES256_CBC; 
        if (name.equalsIgnoreCase("PBEWithSHA256AndAES_128" )) return aladdin.asn1.ansi.OID.BC_PBE_SHA2_256_PKCS12_AES128_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA256AndAES_192" )) return aladdin.asn1.ansi.OID.BC_PBE_SHA2_256_PKCS12_AES192_CBC;
        if (name.equalsIgnoreCase("PBEWithSHA256AndAES_256" )) return aladdin.asn1.ansi.OID.BC_PBE_SHA2_256_PKCS12_AES256_CBC;
        
        // стандартные алгоритмы шифрования ключа
        if (name.equalsIgnoreCase("DESedeWrap"              )) return aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_TDES192_WRAP;
        if (name.equalsIgnoreCase("AESWrap_128"             )) return aladdin.asn1.ansi.OID.NIST_AES128_WRAP;
        if (name.equalsIgnoreCase("AESWrap_192"             )) return aladdin.asn1.ansi.OID.NIST_AES192_WRAP;
        if (name.equalsIgnoreCase("AESWrap_256"             )) return aladdin.asn1.ansi.OID.NIST_AES256_WRAP;
        
        // стандартные алгоритмы наследования ключа
        if (name.equalsIgnoreCase("MGF1"                    )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1;
        
        // стандартные алгоритмы асимметричного шифрования
        if (name.equalsIgnoreCase("RSA"                     )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA;
        if (name.equalsIgnoreCase("RSA/PKCS1Padding"        )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA;
        if (name.equalsIgnoreCase("RSA/OAEPPadding"         )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP;
        
        // стандартные алгоритмы подписи данных
        if (name.equalsIgnoreCase("MD2withRSA"              )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2; 
        if (name.equalsIgnoreCase("MD5withRSA"              )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5;
        if (name.equalsIgnoreCase("SHA1withRSA"             )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1;
        if (name.equalsIgnoreCase("SHA256withRSA"           )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_256;
        if (name.equalsIgnoreCase("SHA384withRSA"           )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_384;
        if (name.equalsIgnoreCase("SHA512withRSA"           )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512; 
        if (name.equalsIgnoreCase("PSSwithRSA"              )) return aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS;
        if (name.equalsIgnoreCase("SHA1withDSA"             )) return aladdin.asn1.ansi.OID.X957_DSA_SHA1; 
        if (name.equalsIgnoreCase("SHA1withECDSA"           )) return aladdin.asn1.ansi.OID.X962_ECDSA_SHA1;
        if (name.equalsIgnoreCase("SHA256withECDSA"         )) return aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256; 
        if (name.equalsIgnoreCase("SHA384withECDSA"         )) return aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384;
        if (name.equalsIgnoreCase("SHA512withECDSA"         )) return aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512; 

        // стандартные алгоритмы согласования общего ключа
        if (name.equalsIgnoreCase("DiffieHellman"           )) return aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY;
        if (name.equalsIgnoreCase("ECDH"                    )) return aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY;
        
        return name;
    }
}
