namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Фабрика создания объекта для неизвестного типа
	///////////////////////////////////////////////////////////////////////////
	public class ImplicitCreator : IObjectFactory
	{
		// фабрика создания объекта для неизвестного типа
		public static readonly IObjectFactory Factory = new ImplicitCreator(); 

		// проверить допустимость типа
		public bool IsValidTag(Tag tag) { return true; }
  
		// проверить корректность объекта
		public void Validate(IEncodable encodable, bool encode) {} 

        // раскодировать объект
        public IEncodable Decode(IEncodable encodable) { return encodable; }
	}
}
