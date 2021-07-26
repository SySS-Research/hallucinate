package gs.sy.m8.hallucinate.interceptor;

/*
Unfortunately the slight differences in Java pre and post 11, necessitate
using two different interceptors (as the connection field name is different).
Refactoring into shared methods/reuse for most parts is not possible, as this
is not regular Java code, but inserted in the actual method bytecode by ByteBuddy
(enabling access to fields, parameters etc..).

Using code generation would be great, though....
 */