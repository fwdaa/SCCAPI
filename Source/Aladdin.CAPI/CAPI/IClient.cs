using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Пользователь 
    ///////////////////////////////////////////////////////////////////////////
    public interface IClient : IRefObject
    {
        // уникальный идентификатор и сертификаты пользователя
        string GetUniqueID(); Certificate[] EnumerateCertificates(); 
       
        // личный ключ пользователя
        byte[] GetPrivateKey(Certificate certificate, ASN1.ISO.Attributes attributes); 

        // зашифровать данные
        byte[] EncryptData(IRand rand, Culture culture, 
            Certificate certificate, Certificate[] recipientCertificates, 
            CMSData data, ASN1.ISO.Attributes attributes
        );
		// расшифровать данные на личном ключе
		CMSData DecryptData(byte[] contentInfo); 

        // подписать данные
        byte[] SignData(IRand rand, Culture culture, 
            Certificate certificate, CMSData data, 
            ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes
        ); 
    }; 
}
