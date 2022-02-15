using System; 
using System.Security.Cryptography;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Открытый ключ алгоритма
	///////////////////////////////////////////////////////////////////////////
	public abstract class PublicKey : IPublicKey
	{
        // фабрика кодирования
        private KeyFactory keyFactory;

        // конструктор
        public PublicKey(KeyFactory keyFactory) { this.keyFactory = keyFactory; } 
    
        // идентификатор ключа
        public string KeyOID { get { return keyFactory.KeyOID; }} 

        // параметры ключа
        public abstract IParameters Parameters { get; }

        // фабрика кодирования
	    public KeyFactory KeyFactory { get { return keyFactory; }}

        // закодированное представление ключа
        public ASN1.ISO.PKIX.SubjectPublicKeyInfo Encoded 
        { 
            // закодировать открытый ключ
            get { return KeyFactory.EncodePublicKey(this); }
        } 
        // преобразовать тип ключа
        public System.Security.Cryptography.X509Certificates.PublicKey Convert()
        {
            // получить закодированное представление
            ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = Encoded; 

            // указать закодированные параметры
            AsnEncodedData encodedParameters = new AsnEncodedData(
                publicKeyInfo.Algorithm.Parameters.Encoded
            ); 
            // указать закодированное представление ключа
            AsnEncodedData encodedPublicKey = new AsnEncodedData(
                publicKeyInfo.SubjectPublicKey.Encoded
            ); 
            // преобразовать тип ключа
            return new System.Security.Cryptography.X509Certificates.PublicKey(
                new Oid(KeyOID), encodedParameters, encodedPublicKey
            ); 
        }
    }
}
