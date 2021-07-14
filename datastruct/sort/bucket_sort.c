#include <stdio.h>

/* "桶排序"
	输入 0 - 10， 5个分数，从小到大排序输出
*/

int bucklet(void)
{
	int a[11] = {0};
	int i, j, t;

	for(i = 0; i <= 5; i++) //循环读入5个数
	{
		scanf("%d", &t);
		if(t >= 0  && t <= 10)
		a[t]++;
	}

	//正序输出
	for(i = 0; i < 11; i++)
	{
		for(j = 0; j < a[i]; j++)
			printf("%d ", i);
	}
	printf("\n");

	//倒序输出
	for(i = 10; i >= 0; i--)
	{
		for(j = 0; j < a[i]; j++)
			printf("%d ", i);
	}
	printf("\n");


}

int buckletSortTest(void)
{
	bucklet();
}
