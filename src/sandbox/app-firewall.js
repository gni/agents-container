const fs = require("fs");

function block(p) {
    if (!p) return;
    const s = p.toString();
    
    // Harden path checking to prevent relative traversals or directory listing bypasses
    if (s.includes("/run/secrets") || 
        s === "run/secrets" || 
        s.startsWith("run/secrets/") || 
        s.includes("/vault") || 
        s === "vault" || 
        s.startsWith("vault/") || 
        s.includes(".secrets") || 
        s.includes(".env.")) {
        throw new Error("[SYSTEM BLOCK] Access to core credential files is hardware-locked and isolated from the agent runtime.");
    }
}

const hooks = [
    "readFile", "readFileSync", "createReadStream", 
    "writeFile", "writeFileSync", "createWriteStream", "appendFile", "appendFileSync",
    "open", "openSync", 
    "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync",
    "readdir", "readdirSync",
    "copyFile", "copyFileSync", "rename", "renameSync",
    "symlink", "symlinkSync", "link", "linkSync",
    "truncate", "truncateSync", "watch", "watchFile"
];

hooks.forEach(fn => {
    if (fs[fn]) {
        const orig = fs[fn];
        fs[fn] = function(...args) { 
            const p = args[0] ? args[0].toString() : "";
            block(p); 
            // Also check destination argument for copyFile, rename, link, symlink
            if (fn === "copyFile" || fn === "copyFileSync" || fn === "rename" || fn === "renameSync" || fn === "link" || fn === "linkSync" || fn === "symlink" || fn === "symlinkSync") {
                const dest = args[1] ? args[1].toString() : "";
                block(dest);
            }
            return orig.apply(this, args); 
        };
    }
    if (fs.promises && fs.promises[fn]) {
        const origP = fs.promises[fn];
        fs.promises[fn] = async function(...args) { 
            const p = args[0] ? args[0].toString() : "";
            block(p); 
            // Also check destination argument for copyFile, rename, link, symlink
            if (fn === "copyFile" || fn === "rename" || fn === "link" || fn === "symlink") {
                const dest = args[1] ? args[1].toString() : "";
                block(dest);
            }
            return origP.apply(this, args); 
        };
    }
});