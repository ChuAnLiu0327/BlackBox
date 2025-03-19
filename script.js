const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const TARGET_STRING = "BlackBox";
const encoder = new TextEncoder();
const targetBytes = encoder.encode(TARGET_STRING);

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    handleFile(e.dataTransfer.files[0]);
});


fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
});

function showStatusMessage(message) {
    const statusEl = document.getElementById('statusMessage');
    statusEl.textContent = message;
    statusEl.classList.add('visible');
}

function hideStatusMessage() {
    const statusEl = document.getElementById('statusMessage');
    statusEl.classList.remove('visible');
}


async function handleFile(file) {
    try {
        const hasMarker = await checkFileEnd(file);
        showStatusMessage(`正在分析文件: ${file.name}`);
        await new Promise(resolve => setTimeout(resolve, 500)); 

        if (hasMarker) {
            const confirmDecrypt = confirm('文件已加密（检测到BlackBox标记），是否要解密？');
            if (confirmDecrypt) {
                const key = await validateKeyInput('解密');
                if (key) {
                    showStatusMessage(`正在解密文件: ${file.name}`);
                    const decrypted = await processFile(file, key, false);
                    downloadFile(decrypted, file.name.replace(/_encrypted$/, ''));
                    showStatusMessage(`解密完成: ${file.name}`);
                }
            }
        } else {
            const confirmEncrypt = confirm('文件未加密（未检测到BlackBox标记），是否要加密？');
            if (confirmEncrypt) {
                const key = await validateKeyInput('加密');
                if (key) {
                    showStatusMessage(`正在加密文件: ${file.name}`);
                    const encrypted = await processFile(file, key, true);
                    downloadFile(encrypted, `${file.name.replace(/\.[^.]+$/, '')}_encrypted${getFileExtension(file.name)}`);
                    showStatusMessage(`加密完成: ${file.name}`);
                }
            }
        }
    } catch (error) {
        showStatusMessage(`处理失败: ${file.name}`);
        alert('文件处理失败: ' + error.message);
    }finally{
        setTimeout(hideStatusMessage,2000);
    }
}

async function validateKeyInput(action) {
    while (true) {
        const key = prompt(`请输入${action}密钥（16字节长度）：`);
        if (key === null) return null; 
        
        try {
            const isValid = validateKeyLength(key);
            if (isValid) return key;
            alert('密钥必须为16字节长度（通常需要16个ASCII字符）');
        } catch (error) {
            alert(error.message);
        }
    }
}

function validateKeyLength(key) {
    const encoder = new TextEncoder();
    const keyBytes = encoder.encode(key);
    
    if (keyBytes.length !== 32) {
        throw new Error(`密钥长度无效：当前 ${keyBytes.length} 字节，需要 32 字节`);
    }
    

    const decoder = new TextDecoder('utf-8', { fatal: true });
    try {
        decoder.decode(keyBytes);
    } catch {
        throw new Error('密钥包含多字节字符，建议使用ASCII字符');
    }
    
    return true;
}

async function checkFileEnd(file) {
    if (file.size < targetBytes.length) return false;
    
    const blob = file.slice(
        file.size - targetBytes.length, 
        file.size
    );
    const buffer = await blob.arrayBuffer();
    const fileBytes = new Uint8Array(buffer);
    
    return arraysEqual(fileBytes, targetBytes);
}

async function processFile(file, key, encrypt) {
    try
    {
        const fileData = await readFileAsUint8Array(file);

        if (encrypt) {
           
            showStatusMessage(`正在加密数据: ${file.name}`);
            const encryptedData = await encryptAES(fileData, key);

            const result = new Uint8Array(encryptedData.length + targetBytes.length);
            result.set(encryptedData);
            result.set(targetBytes, encryptedData.length);
            return result;
        } else {
            showStatusMessage(`正在解密数据: ${file.name}`);
            
            const dataWithoutMarker = fileData.slice(0, -targetBytes.length);
            return await decryptAES(dataWithoutMarker, key);
        }
    }
    catch (error) {
        throw new Error(`AES ${encrypt ? '加密' : '解密'}失败: ${error.message}`);
    }finally{
        showStatusMessage(`正在保存文件: ${file.name}`);
    }
}


async function encryptAES(data, key) {
    const rawKey = new TextEncoder().encode(key);
    const aesKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-CBC" },
        false,
        ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(16));
    
 
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        aesKey,
        data
    );
    
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv);
    result.set(new Uint8Array(encrypted), iv.length);
    
    return result;
}

async function decryptAES(data, key) {
    const rawKey = new TextEncoder().encode(key);
    const aesKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
    );

    const iv = data.slice(0, 16);
    const encryptedData = data.slice(16);
    
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        aesKey,
        encryptedData
    );
    
    return new Uint8Array(decrypted);
}

function arraysEqual(a, b) {
    return a.length === b.length && 
           a.every((val, i) => val === b[i]);
}

function getFileExtension(filename) {
    const lastDot = filename.lastIndexOf('.');
    return lastDot === -1 ? '' : filename.slice(lastDot);
}

async function readFileAsUint8Array(file) {
    return new Uint8Array(await file.arrayBuffer());
}

function xorCipher(data, key) {
    const keyBytes = encoder.encode(key);
    return data.map((byte, index) => 
        byte ^ keyBytes[index % keyBytes.length]
    );
}

function downloadFile(data, filename) {
    const blob = new Blob([data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}