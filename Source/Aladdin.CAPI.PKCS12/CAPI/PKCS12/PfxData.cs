namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Данные с указанием способа шифрования
	///////////////////////////////////////////////////////////////////////////
    public class PfxData<T> where T : class
    {
        // конструктор
        public PfxData(T content, PfxEncryptor encryptor)
        {
            // сохранить переданные параметры
            Content = content; Encryptor = encryptor; 
        }
        // данные и способ их шифрования
        public readonly T Content; public readonly PfxEncryptor Encryptor; 
    }
}
