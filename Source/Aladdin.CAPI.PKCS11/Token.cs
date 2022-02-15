using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Аппаратное криптографическое устройство
	///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Token : SecurityStore, PCSC.ICard
	{
		// физический считыватель
		private Slot slot;

		// конструктор
		public Token(Provider provider, UInt64 slotID) : base(provider, Scope.System)
        {
	        // сохранить переданные паераметры
	        slot = new Slot(provider, slotID); 
        }
		// конструктор
		public Token(Slot slot) : base(slot.Provider, Scope.System)
        {
	        // сохранить переданные паераметры
	        this.slot = RefObject.AddRef(slot); 
        }
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(slot); base.OnDispose(); 
        }
		// криптографический провайдер
		public new Provider Provider { get { return slot.Provider; }}

		// имя смарт-карты
		public override object Name { get { return slot.Name; }}

		///////////////////////////////////////////////////////////////////////////
		// Интерфейс смарт-карты
		///////////////////////////////////////////////////////////////////////////
		public Slot Slot { get { return slot; }}

		// описание считывателя
		public virtual PCSC.IReader Reader { get { return slot; }}

		// состояние смарт-карты
		public virtual PCSC.CardState GetState()
		{ 
			// проверить состояние считывателя
			return (slot.GetState() == PCSC.ReaderState.Card) ? 

				// вернуть состояние смарт-карты
				PCSC.CardState.Present : PCSC.CardState.Empty; 
		}
		///////////////////////////////////////////////////////////////////////////
		// Управление объектами
		///////////////////////////////////////////////////////////////////////////

		// перечислить апплеты
		public override string[] EnumerateObjects()
        {
            // создать список имен апплетов
            List<String> names = new List<String>(); 
            try {
                // получить список считывателей
                UInt64[] slotList = Provider.Module.GetSlotList(true); 

                // для всех найденных смарт-карт
                for (int i = 0; i < slotList.Length; i++) 
                {
                    // получить имя считывателя
                    SlotInfo slotInfo = Provider.Module.GetSlotInfo(slotList[i]); 

                    // проверить совпадение имен
                    if (slotInfo.SlotDescription != slot.Name) continue; 
                
                    // получить информацию устройства
                    TokenInfo tokenInfo = Provider.Module.GetTokenInfo(slotList[i]);	  
                
                    // добавить имя апплета
                    if (!names.Contains(tokenInfo.Model)) names.Add(tokenInfo.Model); 
                }
            }
            // вернуть имена апплетов
            catch {} return names.ToArray();
        }
		// открыть апплет
		public override SecurityObject OpenObject(object name, FileAccess mode)
        {
            // получить список считывателей
            UInt64[] slotList = Provider.Module.GetSlotList(true); 

            // для всех найденных смарт-карт
            for (int i = 0; i < slotList.Length; i++) 
            {
                // получить информацию устройства
                SlotInfo slotInfo = Provider.Module.GetSlotInfo(slotList[i]);	  

                // проверить совпадение имен
                if (slotInfo.SlotDescription != slot.Name) continue; 

                // получить информацию устройства
                TokenInfo tokenInfo = Provider.Module.GetTokenInfo(slotList[i]);	  
            
                // проверить совпадение имени
                if (tokenInfo.Model == name.ToString())
                {
                    // вернуть объект апплета
                    return new Applet(this, slotList[i]); 
                }
            }
            // при ошибке выбросить исключение
            throw new NotFoundException(); 
        }
	}
}
