namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Создание объекта
	///////////////////////////////////////////////////////////////////////////
	public interface IObjectFactory
	{
		// проверить допустимость типа и объекта
		bool IsValidTag(Tag tag); void Validate(IEncodable obj, bool encode);

        // раскодировать объект
        IEncodable Decode(IEncodable decodable); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Создание объекта
	///////////////////////////////////////////////////////////////////////////
	public interface IObjectFactory<T> : IObjectFactory where T : IEncodable
	{
		// проверить корректность объекта
		void Validate(T obj, bool encode); 

        // раскодировать объект
        new T Decode(IEncodable decodable); 
	}
}
