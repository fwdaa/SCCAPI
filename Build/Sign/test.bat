set a=%cd%
for /f %%s in ('cd') do (
	set tmp=%%s 
	print %tmp%
)
