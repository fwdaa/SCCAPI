namespace Aladdin.CAPI.Bio
{
	///////////////////////////////////////////////////////////////////////////
	// Образец отпечатка для регистрации
	///////////////////////////////////////////////////////////////////////////
    public abstract class EnrollTemplate
    {
        // конструктор
        public EnrollTemplate(Finger finger, object publicData, object privateData)
        {
            // сохранить переданные параметры
            Finger = finger; PublicData = publicData; PrivateData = privateData; 
        }
        // используемый палец
        public readonly Finger Finger;

        // открытые и закрытые данные
        public readonly object PublicData; public readonly object PrivateData;

		// проверить соответствие отпечатка
        public abstract bool Validate(Image image);
    }
}
