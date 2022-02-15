namespace Aladdin.CAPI.Bio
{
	///////////////////////////////////////////////////////////////////////////
	// Образец отпечатка для проверки 
	///////////////////////////////////////////////////////////////////////////
    public class MatchTemplate
    {
        // конструктор
        public MatchTemplate(Finger finger, object validationData)
        {
            // сохранить переданные параметры
            Finger = finger; ValidationData = validationData; 
        }
        // используемый палец и данные для проверки
        public readonly Finger Finger; public readonly object ValidationData;
    }
}
