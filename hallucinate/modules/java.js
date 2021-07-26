const MODULE = 'java';


var launch = mapped(MODULE,'JLI_Launch') || Module.findExportByName(mapped(MODULE,'@lib')  || 'libjli.so', 'JLI_Launch');
if ( launch ) {
    send({'type': 'detect-java'})
}