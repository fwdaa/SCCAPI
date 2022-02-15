using System;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////
	// Описание поля в структуре
	///////////////////////////////////////////////////////////////////////
	public class ObjectInfo
	{
		public readonly IObjectFactory	Factory;	// фабрика создания объекта 
		public readonly Cast			Cast;	    // использование типа
		public readonly Tag				Tag;		// тип объекта
		public readonly IEncodable		Value;		// значение объекта по умолчанию

		public ObjectInfo(IObjectFactory factory, Cast cast, Tag tag, IEncodable value)
		{
			// для CHOICE с изменением типа
			if (factory is Choice && tag != Tag.Any) switch (cast)
			{
				// CHOICE не может использоваться IMPLICIT
				case Cast.N: cast = Cast.E; break; case Cast.O: cast = Cast.EO; break; 
			}
			this.Factory	= factory;				// фабрика создания объекта 
			this.Cast	    = cast;					// использование типа
			this.Tag		= tag;					// тип объекта
			this.Value		= value;				// значение объекта по умолчанию
		}
		public ObjectInfo(IObjectFactory factory, Cast cast, Tag tag) 
		{
			// для CHOICE с изменением типа
			if (factory is Choice && tag != Tag.Any) switch (cast)
			{
				// CHOICE не может использоваться IMPLICIT
				case Cast.N: cast = Cast.E; break; case Cast.O: cast = Cast.EO; break; 
			}
			this.Factory	= factory;				// фабрика создания объекта 
			this.Cast	    = cast;					// использование типа
			this.Tag		= tag;					// тип объекта
			this.Value		= null;					// значение объекта по умолчанию
		}
		public ObjectInfo(IObjectFactory factory, Cast cast)
		{
			this.Factory	= factory;				// фабрика создания объекта 
			this.Cast	    = cast;					// использование типа
			this.Tag		= Tag.Any;				// тип объекта
			this.Value		= null;					// значение объекта по умолчанию
		}
		// признак допустимости типа
		public bool IsValidTag(Tag tag) 
		{
			// проверить допустимость типа
			return (this.Tag == Tag.Any) ? Factory.IsValidTag(tag) : (this.Tag == tag); 
		}
		// проверить корректность объекта
		public void Validate(IEncodable encodable, bool encode)
		{
			// при явном приведении типа
			if ((Cast & Cast.E) != 0)
			{
				// извлечь внутренний объект
				IEncodable inner = Encodable.Decode(encodable.Content);
 
				// проверить корректность объекта
				Factory.Validate(inner, encode); 
			}
			// проверить корректность объекта
			else Factory.Validate(encodable, encode); return;  
		}
        // раскодировать объект
        public IEncodable Decode(IEncodable encodable, bool inject) 
        { 
			// при явном приведении типа
			if ((Cast & Cast.E) != 0)
			{
				// извлечь внутренний объект
				IEncodable inner = Encodable.Decode(encodable.Content);

				// раскодировать внутренний объект
				inner = Factory.Decode(inner); if (inject) return inner; 

                // выполнить приведение типа
                return Explicit.Encode(encodable.Tag, inner); 
            }
			// раскодировать объект
			else return Factory.Decode(encodable);
        }
 	}
}
