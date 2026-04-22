//ywbPath: ./ -r

/*
    Test.UPX.PE32.Unpacked.UNOFFICIAL:0:*:436c616d415620746573742066696c65
    Test.UPX.PE32Plus.Unpacked.UNOFFICIAL:0:*:436c616d415620746573742066696c65
    Test.UPX.ELF32.Unpacked.UNOFFICIAL:0:*:436c616d415620746573742066696c65
    Test.UPX.ELF64.Unpacked.UNOFFICIAL:0:*:436c616d415620746573742066696c65
*/

rule unit_test{
    //"ClamAV test file"
    strings: $ = {436C616D415620746573742066696C65}
    condition: all of them
}



