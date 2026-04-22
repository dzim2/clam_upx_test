// unpack_all.js  (WSH JScript - run with: cscript unpack_all.js [folder] [-64])
// Optional args (any order):
//   cscript unpack_all.js 51        -- run folder 51 only, use clam_upx.exe
//   cscript unpack_all.js -64       -- run all folders, use clam_upx64.exe
//   cscript unpack_all.js 51 -64    -- run folder 51 only, use clam_upx64.exe
//   cscript unpack_all.js -64 51    -- same as above

var shell = new ActiveXObject("WScript.Shell");
var fso   = new ActiveXObject("Scripting.FileSystemObject");

var SCRIPT_DIR = fso.GetFile(WScript.ScriptFullName).ParentFolder.Path;
var TESTS_DIR  = SCRIPT_DIR;
var LOG_FILE   = SCRIPT_DIR + "\\scan_results.log";

var results = [];

// --- parse args (order-independent) ---
var filterFolder = null;
var use64        = false;

for (var ai = 0; ai < WScript.Arguments.length; ai++) {
    var arg = WScript.Arguments(ai);
    if (arg === "-64") {
        use64 = true;
    } else {
        filterFolder = arg;
    }
}

var exeName = use64 ? "clam_upx64.exe" : "clam_upx.exe";
var CLAM_UPX = fso.GetFolder(SCRIPT_DIR).ParentFolder.Path + "\\" + exeName;

var log = fso.CreateTextFile(LOG_FILE, true, false);

function write(msg) {
    WScript.Echo(msg);
    log.WriteLine(msg);
}

function timestamp() {
    var d = new Date();
    function pad(n) { return n < 10 ? "0" + n : n; }
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
           "T" + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
}

function scanFolder(folder) {
    var files = new Enumerator(folder.Files);
    for (; !files.atEnd(); files.moveNext()) {
        var f    = files.item();
        var name = f.Name;
        var dotIdx = name.lastIndexOf(".");
        var ext  = dotIdx === -1 ? "" : name.slice(dotIdx).toLowerCase();
        var stem = dotIdx === -1 ? name : name.slice(0, dotIdx);

        var hasUnderscore = stem.indexOf("_") !== -1;
        var isUnp         = ext === ".unp";

        if (!hasUnderscore || isUnp) continue;

        write("----------------------------------------");
        write("[" + timestamp() + "] FILE: " + f.Path);

        // Delete any stale .unp from a previous run so we can't
        // get a false OK from a file the current run didn't produce.
        var unpPath = f.Path + ".unp";
        if (fso.FileExists(unpPath)) {
            try { fso.DeleteFile(unpPath); } catch(e) {
                write("WARNING: could not delete stale " + unpPath + ": " + e.message);
            }
        }

        var cmd = "\"" + CLAM_UPX + "\" \"" + f.Path + "\"";
        write("CMD: " + cmd);

        try {
            var exec = shell.Exec("cmd /c \"" + cmd + "\" 2>&1");

            var stdout = "";
            while (!exec.StdOut.AtEndOfStream) {
                stdout += exec.StdOut.ReadAll();
            }

            while (exec.Status === 0) WScript.Sleep(50);

            var rc = exec.ExitCode;

            write(stdout.length > 0 ? "OUTPUT:\n" + stdout : "OUTPUT: (none)");
            write("EXIT CODE: " + rc);

            var success = fso.FileExists(unpPath);
            var unpSize = success ? fso.GetFile(unpPath).Size : -1;
            results.push({
                status: success ? "OK  " : "FAIL",
                size:   unpSize,
                path:   f.Path.split(SCRIPT_DIR).join('')
            });

        } catch(e) {
            write("ERROR launching process: " + e.message);
        }
    }

    var subs = new Enumerator(folder.SubFolders);
    for (; !subs.atEnd(); subs.moveNext()) {
        scanFolder(subs.item());
    }
}

write("========================================");
write("clam_upx scan started: " + timestamp());
write("CLAM_UPX: " + CLAM_UPX);
write("TESTS DIR: " + TESTS_DIR);
if (filterFolder) write("FILTER: folder " + filterFolder + " only");
if (use64) write("MODE: 64-bit (" + exeName + ")");
write("========================================");

// Enumerate actual subfolders of TESTS_DIR rather than hardcoding 1-5
var rootFolder = fso.GetFolder(TESTS_DIR);
var subEnum    = new Enumerator(rootFolder.SubFolders);
var folders    = [];
for (; !subEnum.atEnd(); subEnum.moveNext()) {
    folders.push(subEnum.item());
}

// Sort numerically by folder name
folders.sort(function(a, b) {
    return parseInt(a.Name, 10) - parseInt(b.Name, 10);
});

var ran = 0;
for (var i = 0; i < folders.length; i++) {
    var f = folders[i];
    // skip non-numeric folder names (e.g. ver_src, log files etc)
    if (!/^\d+$/.test(f.Name)) continue;
    // apply filter if specified
    if (filterFolder !== null && f.Name !== filterFolder) continue;

    write("\n=== Folder " + f.Name + " ===");
    scanFolder(f);
    ran++;
}

if (ran === 0) {
    if (filterFolder !== null)
        write("ERROR: folder '" + filterFolder + "' not found under " + TESTS_DIR);
    else
        write("WARNING: no numeric folders found.");
}

write("========================================");
write("clam_upx scan finished: " + timestamp());
write("========================================");

write("\n========================================");
write("SUMMARY");
write("========================================");
write("STATUS  SIZE         PATH");
write("------  -----------  ----");
var ok = 0, fail = 0;
for (var r = 0; r < results.length; r++) {
    var sizeStr = results[r].size >= 0 ? String(results[r].size) : "n/a";
    while (sizeStr.length < 11) sizeStr = " " + sizeStr;  // right-align in 11 chars
    write(results[r].status + "  " + sizeStr + "  " + results[r].path);
    if (results[r].status === "OK  ") ok++; else fail++;
}
write("----------------------------------------");
write("PASSED: " + ok + "  FAILED: " + fail + "  TOTAL: " + results.length);
write("========================================");
log.Close();
WScript.Echo("\nLog written to: " + LOG_FILE);
