namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Пара ключей в контейнере
    ///////////////////////////////////////////////////////////////////////////////
    public class ContainerKeyPair 
    {
        // конструктор
        public ContainerKeyPair(SecurityInfo info, 
            byte[] keyID, string keyOID, Certificate certificate)
        {
            // сохранить переданные параметры
            Info = info; KeyID = keyID; KeyOID = keyOID; Certificate = certificate; 
        }
        // информация о контейнере и ключе
        public readonly SecurityInfo Info; public readonly byte[] KeyID; 
        
        // OID ключа и сертификат
        public readonly string KeyOID; public readonly Certificate Certificate;
    }
}
