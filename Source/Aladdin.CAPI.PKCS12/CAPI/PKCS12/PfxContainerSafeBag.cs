namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Конечный элемент контейнера PKCS12 
	///////////////////////////////////////////////////////////////////////////
	public class PfxContainerSafeBag
	{
        // конструктор
        public PfxContainerSafeBag(PfxSafeBag safeBag, byte[] id)
        {
            // сохранить переданные параметры
            SafeBag = safeBag; ID = id;  
        }
        // значение и идентификатор элемента контейнера
        public readonly PfxSafeBag SafeBag; public readonly byte[] ID; 
    }
}
