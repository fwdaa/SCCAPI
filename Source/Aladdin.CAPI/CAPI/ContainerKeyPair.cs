namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Пара ключей в контейнере
    ///////////////////////////////////////////////////////////////////////////////
    public class ContainerKeyPair 
    {
        // конструктор
        public ContainerKeyPair(SecurityInfo info, 
            byte[] keyID, string keyOID, Certificate[] certificateChain)
        {
            // сохранить переданные параметры
            Info = info; KeyID = keyID; KeyOID = keyOID; CertificateChain = certificateChain; 
        }
        // информация о контейнере и ключе
        public readonly SecurityInfo Info; public readonly byte[] KeyID; 
        
        // OID ключа и сертификат
        public readonly string KeyOID; public readonly Certificate[] CertificateChain;
    }
}
