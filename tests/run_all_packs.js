// run_all_packs.js  (WSH JScript - run with: cscript run_all_packs.js [version])
// Optional arg: cscript run_all_packs.js 51
// Runs all versions if no arg given.

/*
    Folder 1 (upx 1.20): 32bit_pe only got _2b and _2d, missing _2e and _lzma. 64bit_pe got nothing. ELFs got nothing.
    Folder 2 (upx 2.02): 32bit_pe got _2b, _2d, _2e but no _lzma. 64bit_pe got nothing. ELFs got all three NRV variants but no _lzma.
    Folder 3 (upx 3.09): 32bit_pe full set. 64bit_pe still nothing. ELFs full set.
    Folder 4 (upx 4.20): Everything full — first version where 64bit_pe works.
    Folder 5 (upx 5.01): Full set everywhere, matches 4.
    Folder 51 (upx 5.1.1): Full set everywhere.

    Gaps are version capability limits, not script bugs.
*/

var shell = new ActiveXObject("WScript.Shell");
var fso   = new ActiveXObject("Scripting.FileSystemObject");

var BASE = "C:\\Users\\home\\Desktop\\clam_upx\\tests";

var UPX_VER = {
    "1":  BASE + "\\upx1.20.exe",
    "2":  BASE + "\\upx2.02.exe",
    "3":  BASE + "\\upx3.09.exe",
    "4":  BASE + "\\upx4.20.exe",
    "5":  BASE + "\\upx5.01.exe",
    "51": BASE + "\\upx5.1.1.exe"
};

var SUBFOLDERS = ["32bit_pe", "64bit_pe", "_32_elf", "_64_elf"];

var PACKED_SUFFIXES = ["_2b", "_2d", "_2e", "_lzma"];

var METHODS = [
    { flag: "--nrv2b", suffix: "_2b"   },
    { flag: "--nrv2d", suffix: "_2d"   },
    { flag: "--nrv2e", suffix: "_2e"   },
    { flag: "--lzma",  suffix: "_lzma" }
];

// --- parse optional version arg ---
var filterVer = null;
if (WScript.Arguments.length > 0) {
    filterVer = WScript.Arguments(0);
    if (!UPX_VER[filterVer]) {
        WScript.Echo("ERROR: unknown version '" + filterVer + "'. Valid: " + (function(){
            var k = []; for (var v in UPX_VER) k.push(v); return k.join(", ");
        })());
        WScript.Quit(1);
    }
    WScript.Echo("Running version " + filterVer + " only.");
} else {
    WScript.Echo("Running all versions.");
}

function isPackedOutput(name) {
    var stem = name.replace(/\.[^.]+$/, "");
    for (var i = 0; i < PACKED_SUFFIXES.length; i++) {
        var s = PACKED_SUFFIXES[i];
        if (stem.slice(-s.length) === s) return true;
    }
    return false;
}

for (var num in UPX_VER) {
    if (filterVer !== null && num !== filterVer) continue;

    var upxExe = UPX_VER[num];

    for (var s = 0; s < SUBFOLDERS.length; s++) {
        var subDir = BASE + "\\" + num + "\\" + SUBFOLDERS[s];

        if (!fso.FolderExists(subDir)) {
            WScript.Echo("SKIP (missing): " + subDir);
            continue;
        }

        var folder = fso.GetFolder(subDir);
        var files  = new Enumerator(folder.Files);

        for (; !files.atEnd(); files.moveNext()) {
            var f    = files.item();
            var name = f.Name;

            if (isPackedOutput(name)) continue;

            var stem = name.replace(/\.[^.]+$/, "");
            var ext  = name.slice(stem.length);

            for (var m = 0; m < METHODS.length; m++) {
                var outPath = subDir + "\\" + stem + METHODS[m].suffix + ext;
                var cmd = "\"" + upxExe + "\" " + METHODS[m].flag + " -o \"" + outPath + "\" \"" + f.Path + "\"";
                WScript.Echo("Running: " + cmd);
                var rc = shell.Run("cmd /c \"" + cmd + "\"", 1, true);
                if (rc !== 0)
                    WScript.Echo("  WARNING: exited " + rc + " for " + outPath);
            }
        }
    }
}

WScript.Echo("All done.");