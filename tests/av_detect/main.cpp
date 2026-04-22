
#include <stdio.h>

//We need a PE and ELF target
//[daily.ldb] Win.Worm.Mydoom-9802011-0;Engine:51-255,Target:1;0&1&2&3&4;5a2070242129;76375f26762566;2c5e7d522c787a6d64;413346382678;484f753c2e38
//[daily.ldb] Unix.Trojan.Mirai-7767733-0;Engine:51-255,Target:6;0&1&2&3&4;387a6b756120;4d55602b313a;4c79313c7034;626b536e2328;767d6a49636e

void main(void) {
	//printf("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

	volatile const char* mydoom = "Z p$!) v7_&v%f ,^}R,xzmd A3F8&x HOu<.8";
	volatile const char* mirai = "8zkua MU`+1: Ly1<p4 bkSn#( v}jIcn";

	printf("oldies but a goodies...\n");
	printf("PE Says Kaboom!%s\n", mydoom);
	printf("Elf Says Kerplow! %s\n", mirai);

}
