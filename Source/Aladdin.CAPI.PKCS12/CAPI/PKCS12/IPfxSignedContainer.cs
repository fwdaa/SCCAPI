namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Подписанный контейнер PKCS12
	///////////////////////////////////////////////////////////////////////////
    public interface IPfxSignedContainer
    {
        // открытый ключ и сертификат
		IPrivateKey SignPrivateKey { get; } Certificate SignCertificate { get; }
 
		// установить ключи
		void SetSignKeys(IPrivateKey privateKey, Certificate certificate); 

        // изменить ключи
		void ChangeSignKeys(IPrivateKey privateKey, Certificate certificate); 
    }
}
