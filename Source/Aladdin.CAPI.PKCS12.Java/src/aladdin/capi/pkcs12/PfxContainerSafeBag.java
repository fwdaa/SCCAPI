package aladdin.capi.pkcs12;

///////////////////////////////////////////////////////////////////////////
// Конечный элемент контейнера PKCS12 
///////////////////////////////////////////////////////////////////////////
public class PfxContainerSafeBag
{
    // конструктор
    public PfxContainerSafeBag(PfxSafeBag safeBag, byte[] id)
    {
        // сохранить переданные параметры
        this.safeBag = safeBag; this.id = id;  
    }
    // значение и идентификатор элемента контейнера
    public final PfxSafeBag safeBag; public final byte[] id; 
}
