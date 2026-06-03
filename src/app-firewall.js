const fs = require("fs");

function block(p) {
    if (!p) return;
    const s = p.toString();
    
    if (s.includes("/run/secrets/") || s.includes("/vault/") || s.includes(".secrets") || s.includes(".env.")) {
        throw new Error("[SYSTEM BLOCK] Access to core credential files is hardware-locked and isolated from the agent runtime.");
    }
}

const hooks = [
    "readFile", "readFileSync", "createReadStream", 
    "writeFile", "writeFileSync", "createWriteStream", "appendFile", "appendFileSync",
    "open", "openSync", 
    "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync",
    "readdir", "readdirSync"
];

hooks.forEach(fn => {
    if (fs[fn]) {
        const orig = fs[fn];
        fs[fn] = function(...args) { 
            const p = args[0] ? args[0].toString() : "";
            block(p); 
            return orig.apply(this, args); 
        };
    }
    if (fs.promises && fs.promises[fn]) {
        const origP = fs.promises[fn];
        fs.promises[fn] = async function(...args) { 
            const p = args[0] ? args[0].toString() : "";
            block(p); 
            return origP.apply(this, args); 
        };
    }
});