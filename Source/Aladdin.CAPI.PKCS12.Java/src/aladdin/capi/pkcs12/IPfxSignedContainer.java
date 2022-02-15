package aladdin.capi.pkcs12;
import aladdin.capi.*; 
import aladdin.capi.Certificate; 
import java.io.*; 
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Подписанный контейнер PKCS12
///////////////////////////////////////////////////////////////////////////
public interface IPfxSignedContainer
{
    // открытый ключ и сертификат
    IPrivateKey signPrivateKey(); Certificate signCertificate();
 
	// установить ключи
	void setSignKeys(IPrivateKey privateKey, Certificate certificate) 
        throws IOException, SignatureException; 

    // изменить ключи
	void changeSignKeys(IPrivateKey privateKey, Certificate certificate) throws IOException; 
}
