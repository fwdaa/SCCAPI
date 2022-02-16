package aladdin.asn1.ansi; 

public final class OID
{
	public static final String X963									= "1.2.840.63";
	public static final String X963_SCHEMES							= "1.2.840.63.0";
	public static final String X963_ECDH_STD_SHA1                   = "1.2.840.63.0.2";
	public static final String X963_ECDH_COFACTOR_SHA1              = "1.2.840.63.0.3";
	public static final String X963_ECMQV_SINGLE_SHA1               = "1.2.840.63.0.16";
	public static final String X963_ECMQV_FULL_SHA1                 = "1.2.840.63.0.17";
    
    public static final String X957									= "1.2.840.10040";
	public static final String X957_HOLD                            = "1.2.840.10040.2"; 
	public static final String X957_HOLD_NONE                       = "1.2.840.10040.2.1"; 
	public static final String X957_HOLD_CALL_ISSUER                = "1.2.840.10040.2.2"; 
	public static final String X957_HOLD_REJECT                     = "1.2.840.10040.2.3"; 
	public static final String X957_ALGORITHMS						= "1.2.840.10040.4";
	public static final String X957_DSA								= "1.2.840.10040.4.1";
	public static final String X957_DSA_SHA1						= "1.2.840.10040.4.3"; 

	public static final String X962									= "1.2.840.10045";
	public static final String X962_FIELD_TYPE						= "1.2.840.10045.1";
	public static final String X962_PRIME_FIELD						= "1.2.840.10045.1.1";
	public static final String X962_C2_FIELD                        = "1.2.840.10045.1.2";
	public static final String X962_C2_BASIS                        = "1.2.840.10045.1.2.1";
	public static final String X962_C2_BASIS_GN                     = "1.2.840.10045.1.2.1.1";
	public static final String X962_C2_BASIS_TP                     = "1.2.840.10045.1.2.1.2";
	public static final String X962_C2_BASIS_PP                     = "1.2.840.10045.1.2.1.3";
	public static final String X962_PUBLIC_KEY_TYPE                 = "1.2.840.10045.2";
	public static final String X962_EC_PUBLIC_KEY					= "1.2.840.10045.2.1"; 
	public static final String X962_EC_PUBLIC_KEY_RESTRICTED    	= "1.2.840.10045.2.2"; 
	public static final String X962_CURVES                          = "1.2.840.10045.3";
	public static final String X962_CURVES_C2                       = "1.2.840.10045.3.0";
	public static final String X962_CURVES_C2PNB163V1               = "1.2.840.10045.3.0.1";
	public static final String X962_CURVES_C2PNB163V2               = "1.2.840.10045.3.0.2";
	public static final String X962_CURVES_C2PNB163V3               = "1.2.840.10045.3.0.3";
	public static final String X962_CURVES_C2PNB176W1               = "1.2.840.10045.3.0.4";
	public static final String X962_CURVES_C2TNB191V1               = "1.2.840.10045.3.0.5";
    public static final String X962_CURVES_C2TNB191V2               = "1.2.840.10045.3.0.6"; 
    public static final String X962_CURVES_C2TNB191V3               = "1.2.840.10045.3.0.7";
    public static final String X962_CURVES_C2ONB191V4               = "1.2.840.10045.3.0.8";
    public static final String X962_CURVES_C2ONB191V5               = "1.2.840.10045.3.0.9";
    public static final String X962_CURVES_C2PNB208W1               = "1.2.840.10045.3.0.10";
    public static final String X962_CURVES_C2TNB239V1               = "1.2.840.10045.3.0.11";
    public static final String X962_CURVES_C2TNB239V2               = "1.2.840.10045.3.0.12";
    public static final String X962_CURVES_C2TNB239V3               = "1.2.840.10045.3.0.13";
    public static final String X962_CURVES_C2ONB239V4               = "1.2.840.10045.3.0.14";
    public static final String X962_CURVES_C2ONB239V5               = "1.2.840.10045.3.0.15";
    public static final String X962_CURVES_C2PNB272W1               = "1.2.840.10045.3.0.16";
    public static final String X962_CURVES_C2PNB304W1               = "1.2.840.10045.3.0.17";
    public static final String X962_CURVES_C2TNB359V1               = "1.2.840.10045.3.0.18";
    public static final String X962_CURVES_C2PNB368W1               = "1.2.840.10045.3.0.19";
    public static final String X962_CURVES_C2TNB431R1               = "1.2.840.10045.3.0.20";     
	public static final String X962_CURVES_PRIME                    = "1.2.840.10045.3.1";
	public static final String X962_CURVES_PRIME192V1               = "1.2.840.10045.3.1.1";
    public static final String X962_CURVES_PRIME192V2               = "1.2.840.10045.3.1.2";
    public static final String X962_CURVES_PRIME192V3               = "1.2.840.10045.3.1.3";
    public static final String X962_CURVES_PRIME239V1               = "1.2.840.10045.3.1.4";
    public static final String X962_CURVES_PRIME239V2               = "1.2.840.10045.3.1.5";
    public static final String X962_CURVES_PRIME239V3               = "1.2.840.10045.3.1.6";
	public static final String X962_CURVES_PRIME256V1               = "1.2.840.10045.3.1.7";
	public static final String X962_EC_SIG_TYPE                     = "1.2.840.10045.4";
	public static final String X962_ECDSA_SHA1                      = "1.2.840.10045.4.1";
	public static final String X962_ECDSA_RECOMMENDED               = "1.2.840.10045.4.2";
	public static final String X962_ECDSA_SPECIFIED                 = "1.2.840.10045.4.3";
	public static final String X962_ECDSA_SHA2_224                  = "1.2.840.10045.4.3.1";
	public static final String X962_ECDSA_SHA2_256                  = "1.2.840.10045.4.3.2";
	public static final String X962_ECDSA_SHA2_384                  = "1.2.840.10045.4.3.3";
	public static final String X962_ECDSA_SHA2_512                  = "1.2.840.10045.4.3.4";

    public static final String X942									= "1.2.840.10046";
	public static final String X942_PUBLIC_KEY_TYPE 				= "1.2.840.10046.2";
	public static final String X942_DH_PUBLIC_KEY					= "1.2.840.10046.2.1"; 

	public static final String ENTRUST                              = "1.2.840.113533.7"; 
	public static final String ENTRUST_ALGS                         = "1.2.840.113533.7.66"; 
	public static final String ENTRUST_PBMAC                        = "1.2.840.113533.7.66.13"; 
    
	public static final String RSA									= "1.2.840.113549"; 
	public static final String RSA_DIGEST							= "1.2.840.113549.2"; 
	public static final String RSA_MD2								= "1.2.840.113549.2.2"; 
	public static final String RSA_MD4								= "1.2.840.113549.2.4"; 
	public static final String RSA_MD5								= "1.2.840.113549.2.5"; 
	public static final String RSA_HMAC_SHA1						= "1.2.840.113549.2.7"; 
	public static final String RSA_HMAC_SHA2_224					= "1.2.840.113549.2.8"; 
	public static final String RSA_HMAC_SHA2_256					= "1.2.840.113549.2.9"; 
	public static final String RSA_HMAC_SHA2_384					= "1.2.840.113549.2.10"; 
	public static final String RSA_HMAC_SHA2_512					= "1.2.840.113549.2.11";
	public static final String RSA_HMAC_SHA2_512_224    			= "1.2.840.113549.2.12";
	public static final String RSA_HMAC_SHA2_512_256    			= "1.2.840.113549.2.13";
    
	public static final String RSA_ENCRYPTION						= "1.2.840.113549.3"; 
	public static final String RSA_RC2_CBC							= "1.2.840.113549.3.2"; 
	public static final String RSA_RC2_ECB  						= "1.2.840.113549.3.3"; 
	public static final String RSA_RC4        						= "1.2.840.113549.3.4"; 
	public static final String RSA_DESX_CBC							= "1.2.840.113549.3.6"; 
	public static final String RSA_TDES192_CBC						= "1.2.840.113549.3.7"; 
	public static final String RSA_RC5_CBC							= "1.2.840.113549.3.8"; 
	public static final String RSA_RC5_CBC_PAD						= "1.2.840.113549.3.9"; 
    
	public static final String BC									= "1.3.6.1.4.1.22554";
	public static final String BC_PBE                               = "1.3.6.1.4.1.22554.1";
	public static final String BC_PBE_SHA1                          = "1.3.6.1.4.1.22554.1.1";
	public static final String BC_PBE_SHA1_PKCS5                    = "1.3.6.1.4.1.22554.1.1.1";
	public static final String BC_PBE_SHA1_PKCS12                   = "1.3.6.1.4.1.22554.1.1.2";
	public static final String BC_PBE_SHA1_PKCS12_AES               = "1.3.6.1.4.1.22554.1.1.2.1";
	public static final String BC_PBE_SHA1_PKCS12_AES128_CBC        = "1.3.6.1.4.1.22554.1.1.2.1.2";
	public static final String BC_PBE_SHA1_PKCS12_AES192_CBC        = "1.3.6.1.4.1.22554.1.1.2.1.22"; 
	public static final String BC_PBE_SHA1_PKCS12_AES256_CBC        = "1.3.6.1.4.1.22554.1.1.2.1.42"; 
	public static final String BC_PBE_SHA2                          = "1.3.6.1.4.1.22554.1.2";
	public static final String BC_PBE_SHA2_256                      = "1.3.6.1.4.1.22554.1.2.1";
	public static final String BC_PBE_SHA2_256_PKCS5                = "1.3.6.1.4.1.22554.1.2.1.1";
	public static final String BC_PBE_SHA2_256_PKCS12               = "1.3.6.1.4.1.22554.1.2.1.2";
	public static final String BC_PBE_SHA2_256_PKCS12_AES           = "1.3.6.1.4.1.22554.1.2.1.2.1";
	public static final String BC_PBE_SHA2_256_PKCS12_AES128_CBC    = "1.3.6.1.4.1.22554.1.2.1.2.1.2";
	public static final String BC_PBE_SHA2_256_PKCS12_AES192_CBC    = "1.3.6.1.4.1.22554.1.2.1.2.1.22"; 
	public static final String BC_PBE_SHA2_256_PKCS12_AES256_CBC    = "1.3.6.1.4.1.22554.1.2.1.2.1.42"; 
	public static final String BC_PBE_SHA2_384                      = "1.3.6.1.4.1.22554.1.2.2";
	public static final String BC_PBE_SHA2_512                      = "1.3.6.1.4.1.22554.1.2.3";
	public static final String BC_PBE_SHA2_224                      = "1.3.6.1.4.1.22554.1.2.4";
    
	public static final String IPSEC								= "1.3.6.1.5.5.8";
	public static final String IPSEC_HMAC							= "1.3.6.1.5.5.8.1";
	public static final String IPSEC_HMAC_MD5						= "1.3.6.1.5.5.8.1.1"; 
	public static final String IPSEC_HMAC_SHA1						= "1.3.6.1.5.5.8.1.2"; 
	public static final String IPSEC_HMAC_TIGER						= "1.3.6.1.5.5.8.1.3"; 
	public static final String IPSEC_HMAC_RIPEMD160					= "1.3.6.1.5.5.8.1.4"; 

	public static final String SSIG									= "1.3.14.3"; 
	public static final String SSIG_ALGORITHMS						= "1.3.14.3.2"; 
    public static final String SSIG_RSA_MD4                         = "1.3.14.3.2.4";
	public static final String SSIG_DES_ECB							= "1.3.14.3.2.6";
	public static final String SSIG_DES_CBC							= "1.3.14.3.2.7";
	public static final String SSIG_DES_OFB							= "1.3.14.3.2.8";
	public static final String SSIG_DES_CFB							= "1.3.14.3.2.9";
	public static final String SSIG_DES_MAC							= "1.3.14.3.2.10";
	public static final String SSIG_RSA_SIGN   						= "1.3.14.3.2.11";
	public static final String SSIG_DSA     						= "1.3.14.3.2.12";
	public static final String SSIG_DSA_SHA    						= "1.3.14.3.2.13";
	public static final String SSIG_RSA_SHA                         = "1.3.14.3.2.15";
	public static final String SSIG_TDES_ECB						= "1.3.14.3.2.17";
	public static final String SSIG_SHA  							= "1.3.14.3.2.18";
    public static final String SSIG_RSA_KEYX                        = "1.3.14.3.2.22";
    public static final String SSIG_RSA_MD2                         = "1.3.14.3.2.24";
	public static final String SSIG_RSA_MD5                         = "1.3.14.3.2.25";
	public static final String SSIG_SHA1							= "1.3.14.3.2.26";
	public static final String SSIG_DSA_SHA1        				= "1.3.14.3.2.27";
	public static final String SSIG_RSA_SHA1        				= "1.3.14.3.2.29";

	public static final String TT									= "1.3.36"; 
	public static final String TT_ALGORITHMS						= "1.3.36.3"; 
	public static final String TT_ENCRYPTION						= "1.3.36.3.1";
	public static final String TT_DES								= "1.3.36.3.1.1";
	public static final String TT_DES_ECB							= "1.3.36.3.1.1.1";
	public static final String TT_DES_ECB_PAD						= "1.3.36.3.1.1.1.1";
	public static final String TT_DES_CBC							= "1.3.36.3.1.1.2";
	public static final String TT_DES_CBC_PAD						= "1.3.36.3.1.1.2.1";
	public static final String TT_TDES192							= "1.3.36.3.1.3";
	public static final String TT_TDES192_ECB						= "1.3.36.3.1.3.1";
	public static final String TT_TDES192_ECB_PAD					= "1.3.36.3.1.3.1.1";
	public static final String TT_TDES192_CBC						= "1.3.36.3.1.3.2";
	public static final String TT_TDES192_CBC_PAD					= "1.3.36.3.1.3.2.1";
	public static final String TT_HASH								= "1.3.36.3.2";
	public static final String TT_RIPEMD160							= "1.3.36.3.2.1";
	public static final String TT_RIPEMD128							= "1.3.36.3.2.2";
	public static final String TT_RIPEMD256							= "1.3.36.3.2.3";
	public static final String TT_SIGN								= "1.3.36.3.3";
	public static final String TT_RSA								= "1.3.36.3.3.1"; 
	public static final String TT_RSA_SHA1  						= "1.3.36.3.3.1.1"; 
	public static final String TT_RSA_RIPEMD160						= "1.3.36.3.3.1.2"; 
	public static final String TT_RSA_RIPEMD128						= "1.3.36.3.3.1.3"; 
	public static final String TT_RSA_RIPEMD256						= "1.3.36.3.3.1.4"; 

 	public static final String CERTICOM                             = "1.3.132";
 	public static final String CERTICOM_CURVES                      = "1.3.132.0";
 	public static final String CERTICOM_CURVES_SECT163K1            = "1.3.132.0.1"; 
 	public static final String CERTICOM_CURVES_SECT163R1            = "1.3.132.0.2"; 
 	public static final String CERTICOM_CURVES_SECT239K1            = "1.3.132.0.3";
 	public static final String CERTICOM_CURVES_SECT113R1            = "1.3.132.0.4";
 	public static final String CERTICOM_CURVES_SECT113R2            = "1.3.132.0.5";
 	public static final String CERTICOM_CURVES_SECP112R1            = "1.3.132.0.6";
 	public static final String CERTICOM_CURVES_SECP112R2            = "1.3.132.0.7";
 	public static final String CERTICOM_CURVES_SECP160R1            = "1.3.132.0.8";
 	public static final String CERTICOM_CURVES_SECP160K1            = "1.3.132.0.9";
 	public static final String CERTICOM_CURVES_SECP256K1            = "1.3.132.0.10"; 
	public static final String CERTICOM_CURVES_SECT163R2            = "1.3.132.0.15"; 
	public static final String CERTICOM_CURVES_SECT283K1            = "1.3.132.0.16"; 
	public static final String CERTICOM_CURVES_SECT283R1            = "1.3.132.0.17"; 
	public static final String CERTICOM_CURVES_SECT131R1            = "1.3.132.0.22";
	public static final String CERTICOM_CURVES_SECT131R2            = "1.3.132.0.23";
	public static final String CERTICOM_CURVES_SECT193R1            = "1.3.132.0.24";
	public static final String CERTICOM_CURVES_SECT193R2            = "1.3.132.0.25";
	public static final String CERTICOM_CURVES_SECT233K1            = "1.3.132.0.26"; 
	public static final String CERTICOM_CURVES_SECT233R1            = "1.3.132.0.27"; 
	public static final String CERTICOM_CURVES_SECP128R1            = "1.3.132.0.28";
	public static final String CERTICOM_CURVES_SECP128R2            = "1.3.132.0.29";
	public static final String CERTICOM_CURVES_SECP160R2            = "1.3.132.0.30";
	public static final String CERTICOM_CURVES_SECP192K1            = "1.3.132.0.31"; 
	public static final String CERTICOM_CURVES_SECP224K1            = "1.3.132.0.32"; 
	public static final String CERTICOM_CURVES_SECP224R1            = "1.3.132.0.33"; 
	public static final String CERTICOM_CURVES_SECP384R1            = "1.3.132.0.34"; 
	public static final String CERTICOM_CURVES_SECP521R1            = "1.3.132.0.35"; 
	public static final String CERTICOM_CURVES_SECT409K1            = "1.3.132.0.36"; 
	public static final String CERTICOM_CURVES_SECT409R1            = "1.3.132.0.37"; 
	public static final String CERTICOM_CURVES_SECT571K1            = "1.3.132.0.38"; 
	public static final String CERTICOM_CURVES_SECT571R1            = "1.3.132.0.39"; 
 	public static final String CERTICOM_SCHEMES                     = "1.3.132.1";
 	public static final String CERTICOM_EC_PUBLIC_KEY_SUPPLEMENTED  = "1.3.132.1.0";
 	public static final String CERTICOM_ECDH_COFACTOR_RECOMMENDED   = "1.3.132.1.1";
 	public static final String CERTICOM_ECDH_COFACTOR_SPECIFIED     = "1.3.132.1.2";
 	public static final String CERTICOM_ECMQV_SINGLE_RECOMMENDED    = "1.3.132.1.3";
 	public static final String CERTICOM_ECMQV_SINGLE_SPECIFIED      = "1.3.132.1.4";
 	public static final String CERTICOM_ECMQV_FULL_RECOMMENDED      = "1.3.132.1.5";
 	public static final String CERTICOM_ECMQV_FULL_SPECIFIED        = "1.3.132.1.6";
 	public static final String CERTICOM_ECIES_RECOMMENDED           = "1.3.132.1.7";
 	public static final String CERTICOM_ECIES_SPECIFIED             = "1.3.132.1.8";
 	public static final String CERTICOM_ECWKT_RECOMMENDED           = "1.3.132.1.9";
 	public static final String CERTICOM_ECWKT_SPECIFIED             = "1.3.132.1.10";
 	public static final String CERTICOM_ECDH_STD                    = "1.3.132.1.11";
 	public static final String CERTICOM_ECDH_STD_SHA2_224           = "1.3.132.1.11.0";
 	public static final String CERTICOM_ECDH_STD_SHA2_256           = "1.3.132.1.11.1";
 	public static final String CERTICOM_ECDH_STD_SHA2_384           = "1.3.132.1.11.2";
 	public static final String CERTICOM_ECDH_STD_SHA2_512           = "1.3.132.1.11.3";
 	public static final String CERTICOM_ECDH                        = "1.3.132.1.12";
 	public static final String CERTICOM_ECMQV                       = "1.3.132.1.13";
 	public static final String CERTICOM_ECDH_COFACTOR               = "1.3.132.1.14";
 	public static final String CERTICOM_ECDH_COFACTOR_SHA2_224      = "1.3.132.1.14.0";
 	public static final String CERTICOM_ECDH_COFACTOR_SHA2_256      = "1.3.132.1.14.1";
 	public static final String CERTICOM_ECDH_COFACTOR_SHA2_384      = "1.3.132.1.14.2";
 	public static final String CERTICOM_ECDH_COFACTOR_SHA2_512      = "1.3.132.1.14.3";
 	public static final String CERTICOM_ECMQV_SINGLE                = "1.3.132.1.15";
 	public static final String CERTICOM_ECMQV_SINGLE_SHA2_224       = "1.3.132.1.15.0";
 	public static final String CERTICOM_ECMQV_SINGLE_SHA2_256       = "1.3.132.1.15.1";
 	public static final String CERTICOM_ECMQV_SINGLE_SHA2_384       = "1.3.132.1.15.2";
 	public static final String CERTICOM_ECMQV_SINGLE_SHA2_512       = "1.3.132.1.15.3";
 	public static final String CERTICOM_ECMQV_FULL                  = "1.3.132.1.16";
 	public static final String CERTICOM_ECMQV_FULL_SHA2_224         = "1.3.132.1.16.0";
 	public static final String CERTICOM_ECMQV_FULL_SHA2_256         = "1.3.132.1.16.1";
 	public static final String CERTICOM_ECMQV_FULL_SHA2_384         = "1.3.132.1.16.2";
 	public static final String CERTICOM_ECMQV_FULL_SHA2_512         = "1.3.132.1.16.3";
 	public static final String CERTICOM_KDF                         = "1.3.132.1.17";
 	public static final String CERTICOM_KDF_X963                    = "1.3.132.1.17.0";
 	public static final String CERTICOM_KDF_NIST_CONCAT             = "1.3.132.1.17.1";
 	public static final String CERTICOM_KDF_TLS                     = "1.3.132.1.17.2";
 	public static final String CERTICOM_KDF_IKEV2                   = "1.3.132.1.17.3";
 	public static final String CERTICOM_ECIES_XOR                   = "1.3.132.1.18";
 	public static final String CERTICOM_ECIES_TDES192_CBC           = "1.3.132.1.19";
 	public static final String CERTICOM_ECIES_AES_CBC               = "1.3.132.1.20";
 	public static final String CERTICOM_ECIES_AES128_CBC            = "1.3.132.1.20.0";
 	public static final String CERTICOM_ECIES_AES192_CBC            = "1.3.132.1.20.1";
 	public static final String CERTICOM_ECIES_AES256_CBC            = "1.3.132.1.20.2";
 	public static final String CERTICOM_ECIES_AES_CTR               = "1.3.132.1.21";
 	public static final String CERTICOM_ECIES_AES128_CTR            = "1.3.132.1.21.0";
 	public static final String CERTICOM_ECIES_AES192_CTR            = "1.3.132.1.21.1";
 	public static final String CERTICOM_ECIES_AES256_CTR            = "1.3.132.1.21.2";
 	public static final String CERTICOM_ECIES_HMAC_FULL             = "1.3.132.1.22";
 	public static final String CERTICOM_ECIES_HMAC_HALF             = "1.3.132.1.23";
 	public static final String CERTICOM_ECIES_CMAC_AES              = "1.3.132.1.24";
 	public static final String CERTICOM_ECIES_CMAC_AES128           = "1.3.132.1.24.0";
 	public static final String CERTICOM_ECIES_CMAC_AES192           = "1.3.132.1.24.1";
 	public static final String CERTICOM_ECIES_CMAC_AES256           = "1.3.132.1.24.2";
 	public static final String CERTICOM_ECWKT_AES_KEY_WRAP          = "1.3.132.1.25";
 	public static final String CERTICOM_ECWKT_AES128_KEY_WRAP       = "1.3.132.1.25.0";
 	public static final String CERTICOM_ECWKT_AES192_KEY_WRAP       = "1.3.132.1.25.1";
 	public static final String CERTICOM_ECWKT_AES256_KEY_WRAP       = "1.3.132.1.25.2";
    
	public static final String INFOSEC      						= "2.16.840.1.101.2.1"; 
	public static final String INFOSEC_ALGORITHMS					= "2.16.840.1.101.2.1.1"; 
	public static final String INFOSEC_SKIPJACK_CBC              	= "2.16.840.1.101.2.1.1.4"; 
	public static final String INFOSEC_KEA          				= "2.16.840.1.101.2.1.1.22"; 
	public static final String INFOSEC_SKIPJACK_KEY_WRAP 			= "2.16.840.1.101.2.1.1.23"; 
	public static final String INFOSEC_KEA_AGREEMENT                = "2.16.840.1.101.2.1.1.24"; 

    public static final String NIST         						= "2.16.840.1.101.3"; 
    public static final String NIST_ALGORITHMS						= "2.16.840.1.101.3.4"; 
	public static final String NIST_AES								= "2.16.840.1.101.3.4.1"; 
	public static final String NIST_AES128_ECB						= "2.16.840.1.101.3.4.1.1"; 
	public static final String NIST_AES128_CBC						= "2.16.840.1.101.3.4.1.2"; 
	public static final String NIST_AES128_OFB						= "2.16.840.1.101.3.4.1.3"; 
	public static final String NIST_AES128_CFB						= "2.16.840.1.101.3.4.1.4"; 
	public static final String NIST_AES128_WRAP						= "2.16.840.1.101.3.4.1.5"; 
	public static final String NIST_AES128_GCM						= "2.16.840.1.101.3.4.1.6"; 
	public static final String NIST_AES128_CCM						= "2.16.840.1.101.3.4.1.7"; 
	public static final String NIST_AES128_WRAP_PAD					= "2.16.840.1.101.3.4.1.8"; 
	public static final String NIST_AES192_ECB						= "2.16.840.1.101.3.4.1.21"; 
	public static final String NIST_AES192_CBC						= "2.16.840.1.101.3.4.1.22"; 
	public static final String NIST_AES192_OFB						= "2.16.840.1.101.3.4.1.23"; 
	public static final String NIST_AES192_CFB						= "2.16.840.1.101.3.4.1.24"; 
	public static final String NIST_AES192_WRAP						= "2.16.840.1.101.3.4.1.25"; 
	public static final String NIST_AES192_GCM						= "2.16.840.1.101.3.4.1.26"; 
	public static final String NIST_AES192_CCM						= "2.16.840.1.101.3.4.1.27"; 
	public static final String NIST_AES192_WRAP_PAD					= "2.16.840.1.101.3.4.1.28"; 
	public static final String NIST_AES256_ECB						= "2.16.840.1.101.3.4.1.41"; 
	public static final String NIST_AES256_CBC						= "2.16.840.1.101.3.4.1.42"; 
	public static final String NIST_AES256_OFB						= "2.16.840.1.101.3.4.1.43"; 
	public static final String NIST_AES256_CFB						= "2.16.840.1.101.3.4.1.44"; 
	public static final String NIST_AES256_WRAP						= "2.16.840.1.101.3.4.1.45"; 
	public static final String NIST_AES256_GCM						= "2.16.840.1.101.3.4.1.46"; 
	public static final String NIST_AES256_CCM						= "2.16.840.1.101.3.4.1.47"; 
	public static final String NIST_AES256_WRAP_PAD					= "2.16.840.1.101.3.4.1.48"; 
	public static final String NIST_HASH    						= "2.16.840.1.101.3.4.2"; 
	public static final String NIST_SHA2_256						= "2.16.840.1.101.3.4.2.1"; 
	public static final String NIST_SHA2_384						= "2.16.840.1.101.3.4.2.2"; 
	public static final String NIST_SHA2_512						= "2.16.840.1.101.3.4.2.3"; 
	public static final String NIST_SHA2_224						= "2.16.840.1.101.3.4.2.4"; 
	public static final String NIST_SHA2_512_224  					= "2.16.840.1.101.3.4.2.5"; 
	public static final String NIST_SHA2_512_256  					= "2.16.840.1.101.3.4.2.6"; 
	public static final String NIST_SHA3_224						= "2.16.840.1.101.3.4.2.7"; 
	public static final String NIST_SHA3_256						= "2.16.840.1.101.3.4.2.8"; 
	public static final String NIST_SHA3_384						= "2.16.840.1.101.3.4.2.9"; 
	public static final String NIST_SHA3_512						= "2.16.840.1.101.3.4.2.10"; 
	public static final String NIST_SHAKE_128						= "2.16.840.1.101.3.4.2.11"; 
	public static final String NIST_SHAKE_256						= "2.16.840.1.101.3.4.2.12"; 
	public static final String NIST_SIGN    						= "2.16.840.1.101.3.4.3"; 
	public static final String NIST_DSA_SHA2_224 					= "2.16.840.1.101.3.4.3.1"; 
	public static final String NIST_DSA_SHA2_256 					= "2.16.840.1.101.3.4.3.2"; 
	public static final String NIST_DSA_SHA2_384 					= "2.16.840.1.101.3.4.3.3"; 
	public static final String NIST_DSA_SHA2_512 					= "2.16.840.1.101.3.4.3.4"; 
	public static final String NIST_RSA_SHA3_224 					= "2.16.840.1.101.3.4.3.13"; 
	public static final String NIST_RSA_SHA3_256 					= "2.16.840.1.101.3.4.3.14"; 
	public static final String NIST_RSA_SHA3_384 					= "2.16.840.1.101.3.4.3.15"; 
	public static final String NIST_RSA_SHA3_512 					= "2.16.840.1.101.3.4.3.16"; 
}