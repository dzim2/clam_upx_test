

the test suite include automated packing/unpacking for upx versions 1 - 5.1.1

top level dir contains various major releases of upx.exe 1-5

work folders 1-5 represent the major version number. 

Each work folder contains the following safe samples:

	./32bit_pe/test32.exe
	./64bit_pe/x64Helper.exe
	./_32_elf/upx
	./_64_elf/upx

cscript run_all_packs.js will run each upx version on our work folder structure. 
(one hardcoded path still)

unpack_all.js will run ./../clam_upx.exe on all the files it finds in work dirs that
have an underscore in the file name and not the .unp extension. (all packs)
you can specify a specific version like 51 and also test the 64 bit build with -64
It will also delete any stale *.unp files to make sure its a clean test.

clean.js can be run on its own and will also delete all the *.unp files 


