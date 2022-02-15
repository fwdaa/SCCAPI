#include "stdafx.h"
#include "stsnist.h"
#include "cprob.h"  

////////////////////////////////////////////////////////////////////////////////////
// 2.3 Runs Test
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
////////////////////////////////////////////////////////////////////////////////////
bool RunsTest(const BitSequence* epsilon, size_t n)
{
	// ���������������� ����������
	size_t S = 0; size_t V = 1; 

	// ���������� ����� ������ � ������������������
	for (size_t k = 0; k < n; k++) if (epsilon[k]) S++;

	// ��������� 2.3.4.1 � ��������� pi * (1-pi)
	double pi = (double)S / n; double p = pi * (1- pi); 

	// ��������� 2.3.4.2
	if (fabs(pi - 0.5) > 2.0 / sqrt((double)n)) return false;

	// ��������� 2.3.4.3
	for (size_t k = 1; k < n; k++)
	{
		// ���������� ����� �������� ������������
		if (epsilon[k] != epsilon[k-1]) V++;
	}
	// ��������� 2.3.4.4
	double p_value = erfc(fabs(V - 2.0 * n * p) / (2.0 * sqrt(2.0 * n) * p)); 

	// ��������� 2.3.5
	return (p_value >= 0.01); 
}
