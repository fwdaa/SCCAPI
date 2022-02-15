using System;
using System.Diagnostics.CodeAnalysis;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Личный ключ RSA
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class PrivateKey : CAPI.PKCS11.PrivateKey, ANSI.RSA.IPrivateKey
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // атрибуты ключа
        private CAPI.PKCS11.Attributes keyAttributes; 
    
	    private Math.BigInteger modulus;		// параметр N
	    private Math.BigInteger publicExponent;	// параметр E
	    private Math.BigInteger privateExponent;// параметр D
	    private Math.BigInteger prime1;         // параметр P
	    private Math.BigInteger prime2;         // параметр Q
	    private Math.BigInteger exponent1;		// параметр D (mod P-1)
	    private Math.BigInteger exponent2;		// параметр D (mod Q-1)
	    private Math.BigInteger coefficient;	// параметр Q^{-1}(mod P)
    
	    // атрибуты личного ключа
	    public static CAPI.PKCS11.Attribute[] GetAttributes(
            CAPI.PKCS11.Provider provider, ANSI.RSA.IPrivateKey privateKey)
        {
            // закодировать параметры открытого ключа
            byte[] modulus         = Math.Convert.FromBigInteger(privateKey.Modulus        , Endian); 
            byte[] publicExponent  = Math.Convert.FromBigInteger(privateKey.PublicExponent , Endian);
            byte[] privateExponent = Math.Convert.FromBigInteger(privateKey.PrivateExponent, Endian);
            byte[] prime1          = Math.Convert.FromBigInteger(privateKey.PrimeP         , Endian);
            byte[] prime2          = Math.Convert.FromBigInteger(privateKey.PrimeQ         , Endian);
            byte[] exponent1       = Math.Convert.FromBigInteger(privateKey.PrimeExponentP , Endian);
            byte[] exponent2       = Math.Convert.FromBigInteger(privateKey.PrimeExponentQ , Endian);
            byte[] coefficient     = Math.Convert.FromBigInteger(privateKey.CrtCoefficient , Endian);
        
            // создать набор атрибутов
            return new CAPI.PKCS11.Attribute[] { provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_RSA),

                // указать идентификаторы параметров
                provider.CreateAttribute(API.CKA_MODULUS,          modulus        ), 
                provider.CreateAttribute(API.CKA_PUBLIC_EXPONENT,  publicExponent ), 
                provider.CreateAttribute(API.CKA_PRIVATE_EXPONENT, privateExponent), 
                provider.CreateAttribute(API.CKA_PRIME_1,          prime1         ), 
                provider.CreateAttribute(API.CKA_PRIME_2,          prime2         ), 
                provider.CreateAttribute(API.CKA_EXPONENT_1,       exponent1      ), 
                provider.CreateAttribute(API.CKA_EXPONENT_2,       exponent2      ), 
                provider.CreateAttribute(API.CKA_COEFFICIENT,      coefficient    ) 
            }; 
        }
	    // конструктор 
	    public PrivateKey(CAPI.PKCS11.Provider provider, SecurityObject scope, 
            CAPI.PKCS11.SessionObject obj, ANSI.RSA.IPublicKey publicKey) 
            : base(provider, scope, publicKey.KeyOID)
        {
            // сохранить параметры открытого ключа
            modulus = publicKey.Modulus; publicExponent = publicKey.PublicExponent; 

	        // получить атрибуты ключа
	        keyAttributes = provider.GetKeyAttributes(obj); 
        
            // указать атрибуты открытого ключа
            CAPI.PKCS11.Attribute[] publicAttributes = new CAPI.PKCS11.Attribute[] {
                provider.CreateAttribute(API.CKA_MODULUS,         Math.Convert.FromBigInteger(modulus       , Endian)), 
                provider.CreateAttribute(API.CKA_PUBLIC_EXPONENT, Math.Convert.FromBigInteger(publicExponent, Endian)) 
            }; 
            // добавить атрибуты в список
            keyAttributes = keyAttributes.Join(publicAttributes); 
            
            // при возможности извлечения значения
            if (keyAttributes[API.CKA_EXTRACTABLE].GetByte() != API.CK_FALSE && 
                keyAttributes[API.CKA_SENSITIVE  ].GetByte() == API.CK_FALSE)
            {
                // указать требуемые атрибуты
                CAPI.PKCS11.Attribute[] attributes = new CAPI.PKCS11.Attribute[] {
                    new CAPI.PKCS11.Attribute(API.CKA_PRIVATE_EXPONENT) 
                }; 
                // получить атрибуты ключа
                attributes = obj.GetAttributes(attributes); 
            
                // добавить атрибут в список
                keyAttributes = keyAttributes.Join(attributes); 

                // указать требуемые атрибуты
                attributes = new CAPI.PKCS11.Attribute[] {
                    new CAPI.PKCS11.Attribute(API.CKA_PRIME_1    ), 
                    new CAPI.PKCS11.Attribute(API.CKA_PRIME_2    ), 
                    new CAPI.PKCS11.Attribute(API.CKA_EXPONENT_1 ), 
                    new CAPI.PKCS11.Attribute(API.CKA_EXPONENT_2 ), 
                    new CAPI.PKCS11.Attribute(API.CKA_COEFFICIENT) 
                }; 
                // получить атрибуты ключа
                attributes = obj.GetSafeAttributes(attributes); 
            
                // добавить атрибуты в список
                keyAttributes = keyAttributes.Join(attributes); 
            }
            // при отсутствии на смарт-карте
            if (keyAttributes[API.CKA_TOKEN].GetByte() == API.CK_FALSE)
            {
                // проверить наличие значения
                if (keyAttributes[API.CKA_PRIVATE_EXPONENT] == null)
                {
                    // при ошибке выбросить исключение
                    throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
                }
            }
            // проверить наличие атрибута
            if (keyAttributes[API.CKA_PRIVATE_EXPONENT] == null) privateExponent = null;
            else { 
                // раскодировать значение параметров
                privateExponent = Math.Convert.ToBigInteger(
                    keyAttributes[API.CKA_PRIVATE_EXPONENT].Value, Endian
                );
            }
            if (keyAttributes[API.CKA_PRIME_1] == null) prime1 = null;
            else { 
                // раскодировать значение параметров
                prime1 = Math.Convert.ToBigInteger(
                    keyAttributes[API.CKA_PRIME_1].Value, Endian
                );
            }
            if (keyAttributes[API.CKA_PRIME_2] == null) prime2 = null;
            else { 
                // раскодировать значение параметров
                prime2 = Math.Convert.ToBigInteger(
                    keyAttributes[API.CKA_PRIME_2].Value, Endian
                );
            }
            // при наличии атрибута
            if (keyAttributes[API.CKA_EXPONENT_1] != null)
            {
                // получить значение атрибута
                exponent1 = Math.Convert.ToBigInteger(
                    keyAttributes[API.CKA_EXPONENT_1].Value, Endian
                );
            }
            // вычислить значение параметра
            else exponent1 = (prime1 != null) ? privateExponent.Mod(prime1) : null; 

            // при наличии атрибута
            if (keyAttributes[API.CKA_EXPONENT_2] != null)
            {
                // получить значение атрибута
                exponent2 = Math.Convert.ToBigInteger(
                    keyAttributes[API.CKA_EXPONENT_2].Value, Endian
                );
            }
            // вычислить значение параметра
            else exponent2 = (prime2 != null) ? privateExponent.Mod(prime2) : null; 

            // при наличии атрибута
            if (keyAttributes[API.CKA_COEFFICIENT] != null)
            {
                // получить значение атрибута
                coefficient = Math.Convert.ToBigInteger(
                    keyAttributes[API.CKA_COEFFICIENT].Value, Endian
                );
            }
            // вычислить значение параметра
            else coefficient = (prime1 != null && prime2 != null) ? prime2.ModInverse(prime1) : null;
        }
        // параметры ключа
        public override IParameters Parameters
        {
            // параметры ключа
            get { return new ANSI.RSA.Parameters(modulus.BitLength, publicExponent); }     
        }
	    public Math.BigInteger Modulus        { get { return modulus;        }}
	    public Math.BigInteger PublicExponent { get { return publicExponent; }}

        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
	    public Math.BigInteger PrivateExponent { get 
        { 
            // проверить наличие значения
            if (privateExponent != null) return privateExponent;   

            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
        }}
        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
	    public Math.BigInteger PrimeP { get 
        { 
            // проверить наличие значения
            if (prime1 != null) return prime1;
            
            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
        }}
        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
	    public Math.BigInteger PrimeQ { get 
        { 
            // проверить наличие значения
            if (prime2 != null) return prime2;            

            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
        }}
        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
	    public Math.BigInteger PrimeExponentP { get 
        { 
            // проверить наличие значения
            if (exponent1 != null) return exponent1;            

            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
        }}
        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
	    public Math.BigInteger PrimeExponentQ { get 
        { 
            // проверить наличие значения
            if (exponent2 != null) return exponent2;            

            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
        }}
        [SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
        public Math.BigInteger CrtCoefficient { get 
        { 
            // проверить наличие значения
            if (coefficient != null) return coefficient;            

            // при ошибке выбросить исключение
            throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE);
        }}
        // атрибуты ключа
        protected override CAPI.PKCS11.Attributes KeyAttributes { get { return keyAttributes; }}
    }
}
