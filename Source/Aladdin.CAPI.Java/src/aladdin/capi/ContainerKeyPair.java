package aladdin.capi;

///////////////////////////////////////////////////////////////////////////////
// Пара ключей в контейнере
///////////////////////////////////////////////////////////////////////////////
public class ContainerKeyPair 
{
    // конструктор
    public ContainerKeyPair(SecurityInfo info, byte[] keyID, String keyOID, Certificate certificate)
    {
        // сохранить переданные параметры
        this.info = info; this.keyID = keyID; this.keyOID = keyOID; this.certificate = certificate; 
    }
    // информация о контейнере и ключе
    public final SecurityInfo info; public final byte[] keyID; 
        
    // OID ключа и сертификат
    public final String keyOID; public final Certificate certificate;
}
