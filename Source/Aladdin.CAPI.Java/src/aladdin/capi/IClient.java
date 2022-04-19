package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Пользователь 
///////////////////////////////////////////////////////////////////////////
public interface IClient extends IRefObject
{
    // уникальный идентификатор
    String getUniqueID() throws IOException; 
    
    // сертификаты пользователя
    Certificate[] enumerateCertificates() throws IOException; 
    
    // личный ключ пользователя
    byte[] getPrivateKey(
        Certificate certificate, Attributes attributes) 
        throws IOException; 
    
    // зашифровать данные
    byte[] encryptData(IRand rand, Culture culture, 
        Certificate certificate, Certificate[] recipientCertificates, 
        CMSData data, Attributes attributes
    ) throws IOException;
    
	// расшифровать данные на личном ключе
	CMSData decryptData(byte[] contentInfo) throws IOException; 

    // подписать данные
    byte[] signData(IRand rand, Culture culture,
        Certificate certificate, CMSData data, 
        Attributes[] authAttributes, Attributes[] unauthAttributes
    ) throws IOException; 
}; 
