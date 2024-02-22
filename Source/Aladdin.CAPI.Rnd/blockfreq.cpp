#include "stdafx.h"
#include "stsnist.h"
#include "cprob.h"  

////////////////////////////////////////////////////////////////////////////////////
// 2.2 Frequency Test within a Block
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
////////////////////////////////////////////////////////////////////////////////////
bool FrequencyTest(const BitSequence* epsilon, size_t n, size_t M)
{
	// выполнить 2.2.4.1
	size_t N = n / M; double sum = 0.0;

	// для всех блоков
	for (size_t i = 0; i < N; i++) 
	{
		// определить число единиц в блоке
		double blockSum = 0.0;
		for (size_t j = 0; j < M; j++)
		{
			blockSum += epsilon[i * M + j];
		}
		// выполнить 2.2.4.2
		double pi = blockSum / M;

		// вычислить сумму из 2.2.4.3
		sum += (pi - 0.5) * (pi - 0.5);
	}
	// выполнить 2.2.4.3
	double chi2 = 4.0 * M * sum;

	// выполнить 2.2.4.4
	double p_value = igamc(N / 2.0, chi2 / 2.0);

	// выполнить 2.2.5
	return (p_value >= 0.01); 
}
