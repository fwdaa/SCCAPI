using System; 

namespace Aladdin.Math 
{
    ////////////////////////////////////////////////////////////////////////////////
    // Матрица (unused   , ..., unused       )
    //         (a_0_0    , ..., a_0_{m-1}    )
    //         (  ...    , ...,   ...        )
    //         (a_{m-1}_0, ..., a_{m-1}_{m-1})
    ////////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public sealed class Matrix 
    {
        // столбцы матрицы и число строк
        private Vector[] columns; private int rows; 
    
        // конструктор 
        internal Matrix(Vector[] columns, int rows) 
        {     
            // сохранить переданные параметры
            this.columns = columns; this.rows = rows; 
        } 
        // столбцы матрицы
        public Vector[] Columns { get { return columns; }}

        // число строк матрицы
        public int Rows { get { return rows; }}
    
        // получить значение бита
        public int this[int i, int j] { get { return columns[j][i]; }}
    }
}
