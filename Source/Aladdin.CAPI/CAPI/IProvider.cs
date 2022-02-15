namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Провайдер объектов
	///////////////////////////////////////////////////////////////////////////
	public interface IProvider : IRefObject
	{
        // имя провайдера 
        string Name { get; } 

		// перечислить хранилища объектов
		string[] EnumerateStores(Scope scope); 
        // получить хранилище объектов
        SecurityStore OpenStore(Scope scope, string storeName);     

        // перечислить все объекты
		SecurityInfo[] EnumerateAllObjects(Scope scope); 
	}
}
