#include "stdafx.h"
#include "stsnist.h"
#include "cprob.h"  

////////////////////////////////////////////////////////////////////////////////////
// 2.12 Cumulative Sums (Cusum) Test
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
////////////////////////////////////////////////////////////////////////////////////
bool CusumTest(const BitSequence* epsilon, size_t n, bool mode)
{
	// ������� ��������� �������
	ptrdiff_t z = 0; ptrdiff_t S = 0; double sum1 = 0.0; double sum2 = 0.0;

	// ��� ���� ��������� ������������������
	for (size_t k = 0; k < n; k++) 
	{	
		// ��������� ��������� ����� (2.13.4.2)
		if (!mode) S += (epsilon[        k]) ? 1 : -1; 
		else       S += (epsilon[n - 1 - k]) ? 1 : -1; 

		// ��������� ������������ �������� (2.13.4.3)
		if (S > 0) { if (z <  S) z =  S; }
		else       { if (z < -S) z = -S; }
	}
	// ��������� sqrt(n)
	double sqrtn = sqrt((double)n); ptrdiff_t count = (ptrdiff_t)n; 

	// ��������� 2.13.4.4
	for (ptrdiff_t k = (-count / z + 1) / 4; k <= (count / z - 1) / 4; k++) 
	{
		sum1 += ndtr(((4.0 * k + 1) * z) / sqrtn);
		sum1 -= ndtr(((4.0 * k - 1) * z) / sqrtn);
	}
	// ��������� 2.13.4.4
	for (ptrdiff_t k = (-count / z - 3) / 4; k <= (count / z - 1) / 4; k++) 
	{
		sum2 += ndtr(((4.0 * k + 3) * z) / sqrtn);
		sum2 -= ndtr(((4.0 * k + 1) * z) / sqrtn);
	}
	// ��������� 2.13.4.4
	double p_value = 1.0 - sum1 + sum2;

	// ��������� 2.3.5
	return (p_value >= 0.01); 
}

bool CusumTest(const BitSequence* epsilon, size_t n)
{
	// ��������� �����
	if (!CusumTest(epsilon, n, false)) return false; 
	if (!CusumTest(epsilon, n, true )) return false;  
	return true; 
}
