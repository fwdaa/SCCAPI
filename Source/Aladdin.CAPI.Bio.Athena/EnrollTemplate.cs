namespace Aladdin.CAPI.Bio.Athena
{
 	///////////////////////////////////////////////////////////////////////////
	// Шаблон отпечатка Biomatch Flex для регистрации
	///////////////////////////////////////////////////////////////////////////
    public class EnrollTemplate : Bio.EnrollTemplate
    {
        // биометрическое окружение
        private PreciseBiometrics.BMFH.BioMatch environment; 

		// шаблон отпечатка для регистрации        
        private PreciseBiometrics.BMFH.BMFH_Template template;
        
		// конструктор
        public EnrollTemplate(PreciseBiometrics.BMFH.BioMatch environment, 
			Finger finger, PreciseBiometrics.BMFH.BMFH_Template template)

            // сохранить переданные параметры
            : base(finger, template.BiometricHeader, template.ReferenceData)
        {
			// сохранить переданные параметры
            this.environment = environment; this.template = template;
        }
		// проверить соответствие отпечатка шаблону
        public override bool Validate(Bio.Image image)
        {
            // извлечь внутренний объект
            PreciseBiometrics.BMFH.BM_Image img = ((Image)image).Object; bool check = false;
            
			// проверить соответствие отпечатка шаблону
            environment.ValidateEnrolmentTemplateWithImage(img, template, out check); return check; 
        }
	}
}
