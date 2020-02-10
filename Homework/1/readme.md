## Several Square Roots

Modify the square root program to compute and print the square root of all arguments to the program. There may be zero arguments. You can use `argc`, or you can watch for the NULL pointer in `argv` to iterate through the list, but watch out for registers being clobbered by the functions you call! Call your program `sqrt_list`.

```
$ sqrt_list
$ sqrt_list 16 9 65536 2
sqrt(16.000000) = 4.000000
sqrt(9.000000) = 3.000000
sqrt(65536.000000) = 256.000000
sqrt(2.000000) = 1.414214
```

Two possible solutions to the prior homework are added in the folder.

* `sqrt_list.asm`: walk the array looking for the terminating null pointer
* `sqrt_list_c.asm`: walk the array using a counter