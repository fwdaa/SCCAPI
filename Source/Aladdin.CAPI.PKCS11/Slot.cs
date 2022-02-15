using System;
using System.Diagnostics.CodeAnalysis;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Считыватель для аппаратного криптографического устройства
	///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Slot : RefObject, PCSC.IReader
	{
		// используемый провайдер идентификатор и имя считывателя
		private Provider provider; private UInt64 slotID; private SecurityInfo info;

		// конструктор
		public Slot(Provider provider, UInt64 slotID)
        {
	        // сохранить провайдер
	        this.provider = RefObject.AddRef(provider); this.slotID = slotID; 

	        // получить информацию считывателя
	        SlotInfo slotInfo = provider.Module.GetSlotInfo(slotID); 

	        // сохранить имя считывателя
	        info = new SecurityInfo(Scope.System, slotInfo.SlotDescription, null); 
        }
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(provider); base.OnDispose(); 
        }
		// криптографический провайдер
		public Provider Provider { get { return provider; }}

		// имя считывателя
		public virtual String Name { get { return info.Store; }}
		// идентификатор считывателя
		public UInt64 ID { get { return slotID; }} 

		// перечислить считыватели
		public virtual SecurityInfo[] EnumerateReaders() 
		{
			// перечислить считыватели
			return new SecurityInfo[] { info }; 
		}
		// получить информацию считывателя
		public SlotInfo GetInfo()
        {
	        // получить информацию считывателя
	        return provider.Module.GetSlotInfo(slotID); 
        }
		// состояние считывателя
		public virtual PCSC.ReaderState GetState()
        {
	        try { 
		        // получить информацию считывателя
		        SlotInfo info = GetInfo(); 

		        // проверить состояние считывателя
		        if ((info.Flags & API.CKF_TOKEN_PRESENT) == 0) 
                {
		            // вернуть состояние считывателя
                    return PCSC.ReaderState.Empty; 
                }
		        // вернуть состояние считывателя
		        else return PCSC.ReaderState.Card; 
	        }
            // обработать возможное исключение
	        catch { return PCSC.ReaderState.Unavailable; } 
        }
		// смарт-карта считывателя
		public virtual PCSC.ICard OpenCard()
        {
	        try { 
		        // получить информацию считывателя
		        SlotInfo info = GetInfo(); 

		        // проверить состояние считывателя
		        if ((info.Flags & API.CKF_TOKEN_PRESENT) == 0) return null; 

                // вернуть объект смарт-карты
		        else return new Token(this); 
	        }
            // обработать возможное исключение
	        catch { return null; }
        }
	}
}
