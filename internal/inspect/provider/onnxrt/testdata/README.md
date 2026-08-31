# Test models

`mul_1.onnx` (130 bytes) is from
[microsoft/onnxruntime](https://github.com/microsoft/onnxruntime/blob/main/onnxruntime/test/testdata/mul_1.onnx),
MIT licensed.

It multiplies a 3x2 float input `X` by a baked-in initializer of `[1..6]` and
returns `Y`. Feeding it `[1..6]` therefore produces the squares, which is what
makes it useful here: an arithmetic result proves the binding indexed the right
`OrtApi` members and strided the tensor correctly. A binding that got either
wrong would still return successfully.
