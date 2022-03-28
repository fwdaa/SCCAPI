namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Генерация случайных данных
    ///////////////////////////////////////////////////////////////////////////
	public interface IRand : IAlgorithm
	{
		// сгенерировать случайные данные
		void Generate(byte[] data, int dataOff, int dataLen);

        // описатель окна
        object Window { get; }
	}
}
