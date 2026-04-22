// clean.js  (WSH JScript - run with: cscript clean.js)
// Deletes all .unp files under tests\[1-5] and their subfolders.

var fso = new ActiveXObject("Scripting.FileSystemObject");

var SCRIPT_DIR = WScript.ScriptFullName.replace(/\\[^\\]+$/, "");
var TESTS_DIR  = SCRIPT_DIR //+ "\\tests";

var deleted = 0;

function cleanFolder(folder) {
    var files = new Enumerator(folder.Files);
    for (; !files.atEnd(); files.moveNext()) {
        var f   = files.item();
        var ext = f.Name.slice(f.Name.lastIndexOf(".")).toLowerCase();
        if (ext === ".unp") {
            WScript.Echo("Deleting: " + f.Path);
            f.Delete();
            deleted++;
        }
    }
    var subs = new Enumerator(folder.SubFolders);
    for (; !subs.atEnd(); subs.moveNext()) {
        cleanFolder(subs.item());
    }
}

for (var i = 1; i <= 5; i++) {
    var dir = TESTS_DIR + "\\" + i;
    if (!fso.FolderExists(dir)) continue;
    cleanFolder(fso.GetFolder(dir));
}

var dir = TESTS_DIR + "\\51";
if (fso.FolderExists(dir)) cleanFolder(fso.GetFolder(dir));
	

WScript.Echo("Done. Deleted " + deleted + " .unp file(s).");