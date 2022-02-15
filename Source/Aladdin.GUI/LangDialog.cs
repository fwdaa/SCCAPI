using System;
using System.Windows.Forms;
using System.Drawing;
using System.Globalization;

namespace Aladdin.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог выбора языка
	///////////////////////////////////////////////////////////////////////////
	public partial class LangDialog : Form
	{
		public LangDialog(CultureInfo culture) { InitializeComponent(); 

			// проверить локализацию
			if (culture.TwoLetterISOLanguageName == "en")
			{
				// установить состояние кнопок
				englishButton.Checked = true; 
			}
			// проверить локализацию
			if (culture.TwoLetterISOLanguageName == "ru")
			{
				// установить состояние кнопок
				russianButton.Checked = true; 
			}
		}
		public LangDialog() { InitializeComponent(); }

		public CultureInfo CultureInfo { get 
		{ 
			// проверить состояние кнопок
			if (englishButton.Checked) return new CultureInfo("en"); 
			if (russianButton.Checked) return new CultureInfo("ru"); 

			// вернуть значение по умолчанию
			return new CultureInfo("en");
		}}
	}
}
