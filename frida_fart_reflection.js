//typed by hanbingle,just for fun!!
//email:edunwu@gmail.com

// 本版本可在Frida-16.1.0 + Android12环境下使用
/*使用说明
首先拷贝fart.so和fart64.so到/data/app目录下，并使用chmod 777 设置好权限,然后就可以使用了。
该frida版fart是利用反射的方式实现的函数粒度的脱壳，与使用hook方式实现的方法不同,可以使用spawn和attach两种方式使用。
使用方式1、以spawn方式启动app，等待app进入Activity界面后，执行fart()函数即可
使用方式2、app启动后，使用frida -U直接attach上进程，执行fart()函数即可
高级用法：可以调用dump(classname),传入要处理的类名，只完成对某一个类下的所有函数的CodeItem完成dump，效率更高，dump下来的类函数的所有CodeItem在含有类名的bin文件中。
* */
var addrGetDexFile = null;
var funcGetDexFile = null;
var addrGetObsoleteDexCache = null;
var addrGetCodeItemLength = null;
var funcGetCodeItemLength = null;
var addrBase64_encode = null;
var funcBase64_encode = null;
var addrFreeptr = null;
var funcFreeptr = null;
//需要保存的路径，默认直接保存到sdcard
// var savepath = "/sdcard";
var savepath = "/data/data/com.kanxue.test/reflection"

function DexFile(start, size) {
    this.start = start;
    this.size = size;
}

function ArtMethod(dexfile, artmethodptr) {
    this.dexfile = dexfile;
    this.artmethodptr = artmethodptr;
}

function hasOwnProperty(obj, name) {
    try {
        return obj.hasOwnProperty(name) || name in obj;
    } catch (e) {
        return obj.hasOwnProperty(name);
    }
}
function getHandle(object) {
    if (hasOwnProperty(object, '$handle')) {
        if (object.$handle != undefined) {
            return object.$handle;
        }
    }
    if (hasOwnProperty(object, '$h')) {
        if (object.$h != undefined) {
            return object.$h;
        }
    }
    return null;
}

function dumpcodeitem(methodname, artmethodobj, fileflag) {
    if (artmethodobj != null) {
        var dexfileobj = artmethodobj.dexfile;
        var dexfilebegin = dexfileobj.start;
        var dexfilesize = dexfileobj.size;
        var dexfile_path = savepath + "/" + dexfilesize + "_" + Process.getCurrentThreadId() + ".dex";
        var dexfile_handle = null;
        try {
            dexfile_handle = new File(dexfile_path, "r");
            if (dexfile_handle && dexfile_handle != null) {
                dexfile_handle.close()
            }

        } catch (e) {
            dexfile_handle = new File(dexfile_path, "a+");
            if (dexfile_handle && dexfile_handle != null) {
                var dex_buffer = ptr(dexfilebegin).readByteArray(dexfilesize);
                dexfile_handle.write(dex_buffer);
                dexfile_handle.flush();
                dexfile_handle.close();
                console.log("[dumpdex]:", dexfile_path);
            }
        }
        var artmethodptr = artmethodobj.artmethodptr;
        var dex_code_item_offset_ = Memory.readU32(ptr(artmethodptr).add(8));
        var dex_method_index_ = Memory.readU32(ptr(artmethodptr).add(12));
        if (dex_code_item_offset_ != null && dex_code_item_offset_ > 0) {
            var dir = savepath;
            var file_path = dir + "/" + dexfilesize + "_" + Process.getCurrentThreadId() + "_" + fileflag + ".bin";
            var file_handle = new File(file_path, "a+");
            if (file_handle && file_handle != null) {
                var codeitemstartaddr = ptr(dexfilebegin).add(dex_code_item_offset_);
                var codeitemlength = funcGetCodeItemLength(ptr(codeitemstartaddr));
                if (codeitemlength != null & codeitemlength > 0) {
                    Memory.protect(ptr(codeitemstartaddr), codeitemlength, 'rwx');
                    var base64lengthptr = Memory.alloc(8);
                    var arr = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    Memory.writeByteArray(base64lengthptr, arr);
                    var base64ptr = funcBase64_encode(ptr(codeitemstartaddr), codeitemlength, ptr(base64lengthptr));
                    var b64content = ptr(base64ptr).readCString(base64lengthptr.readInt());
                    funcFreeptr(ptr(base64ptr));
                    var content = "{name:" + methodname + ",method_idx:" + dex_method_index_ + ",offset:" + dex_code_item_offset_ + ",code_item_len:" + codeitemlength + ",ins:" + b64content + "};";
                    file_handle.write(content);
                    file_handle.flush();
                    file_handle.close();
                }

            } else {
                console.log("openfile failed,filepath:", file_path);
            }
        }


    }

}

function init() {
    console.log("go into init," + "Process.arch:" + Process.arch);
    var module_libext = null;
    if (Process.arch === "arm64") {
        module_libext = Module.load("/data/app/fart64.so");
    } else if (Process.arch === "arm") {
        module_libext = Module.load("/data/app/fart.so");
    }
    if (module_libext != null) {
        addrGetDexFile = module_libext.findExportByName("GetDexFile");
        funcGetDexFile = new NativeFunction(addrGetDexFile, "pointer", ["pointer", "pointer"]);
        addrGetCodeItemLength = module_libext.findExportByName("GetCodeItemLength");
        funcGetCodeItemLength = new NativeFunction(addrGetCodeItemLength, "int", ["pointer"]);
        addrBase64_encode = module_libext.findExportByName("Base64_encode");
        funcBase64_encode = new NativeFunction(addrBase64_encode, "pointer", ["pointer", "int", "pointer"]);
        addrFreeptr = module_libext.findExportByName("Freeptr");
        funcFreeptr = new NativeFunction(addrFreeptr, "void", ["pointer"]);
    }
    var symbols = Module.enumerateSymbolsSync("libart.so");
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("ArtMethod") >= 0 && symbol.name.indexOf("GetObsoleteDexCache") >= 0) {
            addrGetObsoleteDexCache = symbol.address;
            break;
        }
    }
}

function dealwithmethod(classname, method) {
    console.log("start dump method:" + classname + "---" + method.toString());
    if(method.toString().indexOf("native") >= 0 || method.toString().indexOf("[L")>=0){
        return
    }
    var jnienv = Java.vm.getEnv();
    var handle = getHandle(method);

    if(handle){
        var ArtMethodptr = jnienv.fromReflectedMethod(ptr(handle));
        var DexFileptr = funcGetDexFile(ptr(ArtMethodptr), ptr(addrGetObsoleteDexCache));
        if (DexFileptr != null) {
            var dexfilebegin = Memory.readPointer(ptr(DexFileptr).add(Process.pointerSize * 1));
            var dexfilesize = Memory.readU32(ptr(DexFileptr).add(Process.pointerSize * 2));
            var dexfileobj = new DexFile(dexfilebegin, dexfilesize);
            if (ArtMethodptr != null) {
                var artmethodobj = new ArtMethod(dexfileobj, ArtMethodptr);
                dumpcodeitem(classname + "->" + method.toString(), artmethodobj, 'all');
            }
        }
    }

}

function dumpmethod(classname, method) {
    console.log("start dump method:" + classname + "---" + method.toString());
    if(method.toString().indexOf("native") >= 0 || method.toString().indexOf("[L")>=0){
        return
    }
    var jnienv = Java.vm.getEnv();
    var handle = getHandle(method);
    
    if( handle ){
        var ArtMethodptr = jnienv.fromReflectedMethod(ptr(handle));
        var DexFileptr = funcGetDexFile(ptr(ArtMethodptr), ptr(addrGetObsoleteDexCache));
    
        if (DexFileptr != null) {
            var dexfilebegin = Memory.readPointer(ptr(DexFileptr).add(Process.pointerSize * 1));
            var dexfilesize = Memory.readU32(ptr(DexFileptr).add(Process.pointerSize * 2));
            console.log(handle);
            var dexfileobj = new DexFile(dexfilebegin, dexfilesize);
            if (ArtMethodptr != null) {
    
                var artmethodobj = new ArtMethod(dexfileobj, ArtMethodptr);
                dumpcodeitem(classname + "->" + method.toString(), artmethodobj, classname);
            }
        }
    }
    
    
}

function dumpclass(classname) {
    if (Java.available) {
        Java.perform(function () {
            console.log("go into enumerateClassLoaders!");
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        var loadclass = loader.loadClass(classname);
                        console.log(loader + "-->loadclass " + classname + " success!");
                        var methods = loadclass.getDeclaredConstructors();
                        console.log(methods);
                        for (var i in methods) {
                            
                            dumpmethod(classname, methods[i]);
                        }
                        methods = loadclass.getDeclaredMethods();
                        for (var i in methods) {
                            dumpmethod(classname, methods[i]);
                        }
                    } catch (e) {
                        console.log("error", e);
                    }

                },
                onComplete: function () {
                    console.log("find  Classloader instance over");
                }
            });
        });
    }
}

function dealwithClassLoader(classloaderobj) {
    if (Java.available) {
        Java.perform(function () {
            try {
                var dexfileclass = Java.use("dalvik.system.DexFile");
                var BaseDexClassLoaderclass = Java.use("dalvik.system.BaseDexClassLoader");
                var DexPathListclass = Java.use("dalvik.system.DexPathList");
                var Elementclass = Java.use("dalvik.system.DexPathList$Element");
                var basedexclassloaderobj = Java.cast(classloaderobj, BaseDexClassLoaderclass);
                var pathlistobj = Java.cast(basedexclassloaderobj.pathList.value, DexPathListclass);
                
                for(var i = 0; i < pathlistobj.dexElements.value.length; i++){
                    var dexElementobj = Java.cast(pathlistobj.dexElements.value[i], Elementclass);
                    if (dexElementobj.dexFile.value) {
                        
                        var dexfileobj = Java.cast(dexElementobj.dexFile.value, dexfileclass);
                        const enumeratorClassNames = dexfileobj.entries();
                        while (enumeratorClassNames.hasMoreElements()) {
                            var classname = enumeratorClassNames.nextElement().toString();
                            console.log("start loadclass->" + classname);
                            try{
                                var loadclass = classloaderobj.loadClass(classname);
                                console.log("after loadclass->" + classname);

                                var methods = loadclass.getDeclaredConstructors();
                                for (var i in methods) {
                                    dealwithmethod(classname, methods[i]);
                                }
    
                                methods = loadclass.getDeclaredMethods();
                                for (var i in methods) {
                                    dealwithmethod(classname, methods[i]);
                                }
                            }
                            catch(e){
                                console.log("error", e);
                            }
                        }
                    }
                }
            } catch (e) {
                console.log(e);
            }

        });
    }


}

function fart() {
    if (Java.available) {
        Java.perform(function () {
            console.log("go into enumerateClassLoaders!");
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    if (loader.toString().indexOf("BootClassLoader") >= 0) {
                        console.log("this is a BootClassLoader!")
                    } else {
                        try {
                            console.log("startdealwithclassloader:", loader, '\n');
                            dealwithClassLoader(loader);
                        } catch (e) {
                            console.log("error", e);
                        }
                    }
                },
                onComplete: function () {
                    console.log("find  Classloader instance over");
                }
            });
        });
    }
}

setImmediate(init);
