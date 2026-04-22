
rule unit_test{
    //"ClamAV test file"
    strings: $ = {436C616D415620746573742066696C65}
    condition: all of them
}

rule simple{
    /*
        echo -n "Elf Says Kerplow!" | xxd -p
        # 456c662053617973204b6572706c6f7721
    */
    strings: $ = {456c662053617973204b6572706c6f7721}
    condition: all of them
}

rule Win_Worm_Mydoom_9802011_0
{
    meta:
        clam_name = "Win.Worm.Mydoom-9802011-0"
        engine = "51-255"

    strings:
        $a0 = { 5A 20 70 24 21 29 }
        $a1 = { 76 37 5F 26 76 25 66 }
        $a2 = { 2C 5E 7D 52 2C 78 7A 6D 64 }
        $a3 = { 41 33 46 38 26 78 }
        $a4 = { 48 4F 75 3C 2E 38 }

    condition:
         uint16(0) == 0x5A4D and  // "MZ"
         all of them
}

rule Unix_Trojan_Mirai_7767733_0
{
    meta:
        clam_name = "Unix.Trojan.Mirai-7767733-0"
        engine = "51-255"
        target = "ELF"

    strings:
        $a0 = { 38 7A 6B 75 61 20 }        // "8zkua "
        $a1 = { 4D 55 60 2B 31 3A }        // "MU`+1:"
        $a2 = { 4C 79 31 3C 70 34 }        // "Ly1<p4"
        $a3 = { 62 6B 53 6E 23 28 }        // "bkSn#("
        $a4 = { 76 7D 6A 49 63 6E }        // "v}jIcn"

    condition:
        uint32(0) == 0x464C457F and  // ELF magic "\x7FELF"
        all of them
}


