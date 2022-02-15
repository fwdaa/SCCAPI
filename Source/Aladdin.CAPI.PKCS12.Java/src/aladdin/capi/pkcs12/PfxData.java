package aladdin.capi.pkcs12;

public class PfxData<T> 
{
    // конструктор
    public PfxData(T content, PfxEncryptor encryptor)
    {
        // сохранить переданные параметры
        this.content = content; this.encryptor = encryptor; 
    }
    // элемент контейнера и способ его зашифрования
    public final T content; public final PfxEncryptor encryptor; 
}
