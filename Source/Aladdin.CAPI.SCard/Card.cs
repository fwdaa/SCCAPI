using System;
using System.IO;
using Aladdin.PCSC; 

namespace Aladdin.CAPI.SCard
{
	///////////////////////////////////////////////////////////////////////////
	// Смарт-карта как хранилище апплетов
	///////////////////////////////////////////////////////////////////////////
	public class Card : SecurityStore
	{
        // внутренняя реализация провайдера и используемая смарт-карта
        private IProviderImpl impl; private string readerName; private PCSC.Card card;

        // конструктор
        public Card(Provider provider, IProviderImpl impl, 
            
            // указать имя смарт-карты
            Scope scope, PCSC.Card card) : base(provider, scope)
        {      
            // сохранить переданные параметры
            this.impl = impl; this.readerName = card.Reader.Name; this.card = card;
        } 
        // используемый провайдер
        public new Provider Provider 
        { 
            // используемый провайдер
            get { return (Provider)base.Provider; }
        }
        // имя считывателя
        public override object Name { get { return readerName; }}
        // смарт-карта апплета
        public PCSC.Card PCSCCard { get { return card; }} 

		///////////////////////////////////////////////////////////////////////
		// Управление объектами
		///////////////////////////////////////////////////////////////////////
		public override string[] EnumerateObjects() 
        { 
            // проверить наличие смарт-карты
            if ((PCSCCard.GetState() & CardState.Present) == CardState.Empty) return new string[0]; 

            // перечислить апплеты
            try { return impl.EnumerateApplets(this); } catch { return new string[0]; }
        }  
		// открыть объект
		public override SecurityObject OpenObject(object name, FileAccess access)
        {
            // проверить наличие смарт-карты
            if ((PCSCCard.GetState() & CardState.Present) == CardState.Empty) 
            {
                // при ошибке выбросить исключение
                throw new NotFoundException(); 
            }
            // открыть апплет
            return impl.OpenApplet(this, name.ToString()); 
        }
	}
}
